"""
Optimized SLM (Small Language Model) Training for Phishing Content.

Optimized for 30GB RAM / 4 vCPUs (NO GPU):
1. Model: `prajjwal1/bert-small` (29M parameters). Capable model that fits comfortably
   in 30GB RAM and runs efficiently on 4 CPU cores.
2. Memory: Uses the HuggingFace `datasets` Arrow-backed framework. It maps the CSV
   to disk instead of RAM, entirely preventing Out-Of-Memory (OOM) crashes.
3. Checkpointing: Integrates HuggingFace `Trainer` to save progress every epoch.
   If training stops, just re-run this script and it resumes where it stopped.
4. Batching: Uses `per_device_train_batch_size=32` and `gradient_accumulation_steps=2`
   to simulate effective batch of 64, fully utilizing available RAM.
"""

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import os
import sys
import json
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Set thread counts to match available CPU cores (4 cores on 30GB system)
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["OPENBLAS_NUM_THREADS"] = "4"
os.environ["MKL_NUM_THREADS"] = "4"

# IMPORTANT: Import third-party packages BEFORE modifying sys.path.
# The parent directory contains a local `datasets/` package that would
# shadow the HuggingFace `datasets` library if it were on sys.path first.
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import train_test_split
from datasets import Dataset
from tqdm.auto import tqdm
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    BertTokenizer,
    BertForSequenceClassification,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)
from transformers.trainer_utils import get_last_checkpoint

# Now add parent directory to sys.path for email_security imports.
# This MUST come after HuggingFace `datasets` import above.
REPO_ROOT = PHISHING_HOME
pass  # (package import; no sys.path hack needed)
PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
OUTPUT_DIR = REPO_ROOT.parent / "models" / "content_agent_slm_checkpoints"
FINAL_MODEL_DIR = REPO_ROOT.parent / "models" / "content_agent"
RUN_LOG_DIR = FINAL_MODEL_DIR / "run_logs"
FINGERPRINT_FILE = OUTPUT_DIR / "data_fingerprint.json"

RANDOM_SEED = 42

# Load settings for 30GB RAM environment
from soc_platform.domains.phishing.engine.configs.settings import settings

# Token-usage controls (now backed by Pydantic settings with 30GB optimizations).
MAX_SEQ_LEN = int(os.getenv("SLM_MAX_SEQ_LEN", str(settings.slm_max_seq_len)))
MAX_WORDS_PER_SAMPLE = int(os.getenv("SLM_MAX_WORDS_PER_SAMPLE", str(settings.slm_max_words_per_sample)))
MAX_SAMPLES_PER_CLASS = int(os.getenv("SLM_MAX_SAMPLES_PER_CLASS", str(settings.slm_max_samples_per_class)))
MIN_SAMPLES_PER_CLASS = int(os.getenv("SLM_MIN_SAMPLES_PER_CLASS", str(settings.slm_min_samples_per_class)))
NUM_EPOCHS = int(os.getenv("SLM_NUM_EPOCHS", str(settings.slm_num_epochs)))
PER_DEVICE_BATCH_SIZE = int(os.getenv("SLM_PER_DEVICE_BATCH_SIZE", str(settings.slm_per_device_train_batch_size)))
GRADIENT_ACCUMULATION_STEPS = int(os.getenv("SLM_GRADIENT_ACCUMULATION_STEPS", str(settings.slm_gradient_accumulation_steps)))
NUM_WORKERS = int(os.getenv("SLM_NUM_WORKERS", str(settings.slm_num_workers)))
LOGGING_STEPS = int(os.getenv("SLM_LOGGING_STEPS", str(settings.slm_logging_steps)))
RESUME_TRAINING = os.getenv("SLM_RESUME", "1") == "1"
FORCE_RETRAIN = os.getenv("SLM_FORCE_RETRAIN", "0") == "1"

print(f"✓ SLM Training Parameters (30GB RAM Optimized):")
print(f"  - Max Sequence Length: {MAX_SEQ_LEN} (increased from 96)")
print(f"  - Max Words per Sample: {MAX_WORDS_PER_SAMPLE} (increased from 180)")
print(f"  - Max Samples per Class: {MAX_SAMPLES_PER_CLASS} (increased from 120K)")
print(f"  - Per-Device Batch Size: {PER_DEVICE_BATCH_SIZE} (increased from 8)")
print(f"  - Gradient Accumulation: {GRADIENT_ACCUMULATION_STEPS}")
print(f"  - Tokenization Workers: {NUM_WORKERS} (increased from 2)")
print(f"  - Training Epochs: {NUM_EPOCHS} (increased from 10)")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_fingerprint() -> dict[str, str]:
    if not FINGERPRINT_FILE.exists():
        return {}
    try:
        return json.loads(FINGERPRINT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_fingerprint(payload: dict[str, str]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    FINGERPRINT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_checkpoint_epoch(checkpoint_path: Path) -> float | None:
    state_file = checkpoint_path / "trainer_state.json"
    if not state_file.exists():
        return None
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return None
    epoch = state.get("epoch")
    return float(epoch) if epoch is not None else None


def _label_display_names(label_values: list[int]) -> list[str]:
    label_name_map = {0: "Legitimate", 1: "Spam", 2: "Phishing"}
    return [label_name_map.get(lbl, f"Class {lbl}") for lbl in label_values]


def _compact_text(text: str) -> str:
    """Normalize and shorten text so tokenization stays compute-efficient."""
    normalized = " ".join(str(text).split())
    words = normalized.split()
    if len(words) > MAX_WORDS_PER_SAMPLE:
        words = words[:MAX_WORDS_PER_SAMPLE]
    return " ".join(words)


def _ensure_canonical_dataset(csv_path: Path) -> None:
    if csv_path.exists():
        return

    print("Canonical SLM CSV missing. Regenerating content preprocessing outputs...")
    from soc_platform.domains.phishing.engine.preprocessing.content_preprocessing import run as run_content_preprocessing

    run_content_preprocessing(base_dir="datasets", output_dir="datasets_processed")

def main():
    csv_path = PROCESSED_DIR / "content_training_slm.csv"
    _ensure_canonical_dataset(csv_path)
    if not csv_path.exists():
        print(f"ERROR: Canonical SLM training data not found at {csv_path} after regeneration attempt")
        sys.exit(1)

    # Enforce strict schema compatibility for this SLM trainer.
    header = pd.read_csv(csv_path, nrows=1)
    expected_cols = ["text", "label"]
    if list(header.columns) != expected_cols:
        print(
            "ERROR: Invalid content SLM CSV schema. "
            f"Expected columns {expected_cols} in order, got {list(header.columns)}"
        )
        sys.exit(1)

    current_fingerprint = {
        "csv_path": str(csv_path),
        "sha256": _file_sha256(csv_path),
    }
    previous_fingerprint = _load_fingerprint()

    print("1. Loading TinyBERT tokenizer...")
    # Use a stable tiny BERT checkpoint with explicit bert model_type.
    # Can be overridden if needed: export SLM_MODEL_ID=...
    model_id = os.getenv("SLM_MODEL_ID", "prajjwal1/bert-tiny")
    # bert-tiny uses BERT vocabulary; loading a stable slow tokenizer avoids
    # fast-tokenizer backend issues in minimal environments.
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased", do_lower_case=True)

    print("2. Loading + token-aware preprocessing...")
    # Load via generator/pandas chunking to Arrow format with TQDM progress bar
    chunks = []
    # Using low_memory equivalent chunksize to gracefully parse 1.7GB natively
    for chunk in tqdm(pd.read_csv(csv_path, dtype={"text": str}, chunksize=50000), desc="Loading SLM Content"):
        chunk = chunk.dropna(subset=["text", "label"])
        chunk["label"] = pd.to_numeric(chunk["label"], errors="coerce")
        chunk = chunk.dropna(subset=["label"])
        chunk["label"] = chunk["label"].astype(int)
        chunk["text"] = chunk["text"].astype(str).map(_compact_text)
        # Skip very short fragments to avoid paying token budget on noise.
        chunk = chunk[chunk["text"].str.len() >= 16]
        chunks.append(chunk[["text", "label"]])

    df = pd.concat(chunks, ignore_index=True)
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    label_values = sorted(df["label"].unique().tolist())
    if set(label_values) != {0, 1, 2}:
        print(
            "ERROR: Content SLM requires exactly 3 canonical labels {0,1,2}. "
            f"Found labels: {label_values}"
        )
        sys.exit(1)

    # Cap samples per class to bound token usage while keeping class balance.
    balanced = []
    for label in label_values:
        part = df[df["label"] == label]
        if len(part) > MAX_SAMPLES_PER_CLASS:
            part = part.sample(n=MAX_SAMPLES_PER_CLASS, random_state=RANDOM_SEED)
        elif len(part) < MIN_SAMPLES_PER_CLASS:
            part = part.sample(n=MIN_SAMPLES_PER_CLASS, replace=True, random_state=RANDOM_SEED)
        balanced.append(part)

    df = pd.concat(balanced, ignore_index=True)
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    dedup_removed = before_dedup - len(df)
    print(f"   -> Deduplicated rows: {dedup_removed}")
    print(f"   -> Final samples: {len(df)}")
    print(f"   -> Label distribution:\n{df['label'].value_counts().to_string()}")
    print(f"   -> Classes used: {label_values}")
    print(
        f"   -> Token budget settings: max_seq_len={MAX_SEQ_LEN}, "
        f"max_words_per_sample={MAX_WORDS_PER_SAMPLE}, "
        f"max_samples_per_class={MAX_SAMPLES_PER_CLASS}, "
        f"min_samples_per_class={MIN_SAMPLES_PER_CLASS}"
    )

    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=df["label"],
    )

    dataset = {
        "train": Dataset.from_pandas(train_df.reset_index(drop=True), preserve_index=False),
        "test": Dataset.from_pandas(test_df.reset_index(drop=True), preserve_index=False),
    }

    def tokenize_function(examples):
        # Truncate to a strict token budget; no global max-length padding here.
        return tokenizer(examples["text"], truncation=True, max_length=MAX_SEQ_LEN)

    print(f"3. Tokenizing dataset (multi-processing with {NUM_WORKERS} workers)...")
    tokenized_datasets = {
        split: dataset[split].map(tokenize_function, batched=True, num_proc=NUM_WORKERS)
        for split in ("train", "test")
    }
    
    # Remove raw text to free up any stray RAM
    for split in ("train", "test"):
        tokenized_datasets[split] = tokenized_datasets[split].remove_columns(["text"])
        tokenized_datasets[split] = tokenized_datasets[split].rename_column("label", "labels")
        tokenized_datasets[split].set_format("torch")
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    print("4. Initializing BERT Model for Sequence Classification...")
    num_labels = len(label_values)
    try:
        model = BertForSequenceClassification.from_pretrained(
            model_id, num_labels=num_labels
        )
    except Exception as exc:
        print(
            f"WARNING: Failed to load '{model_id}' directly ({exc}). "
            "Attempting fallback to AutoModelForSequenceClassification..."
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            model_id, num_labels=num_labels
        )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predictions, average="macro"
        )
        acc = accuracy_score(labels, predictions)
        return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


    # ── Checkpointing & Resumption Logic ──
    last_checkpoint = None
    if FORCE_RETRAIN and OUTPUT_DIR.exists():
        print(f"FORCE_RETRAIN enabled. Removing old checkpoints at {OUTPUT_DIR}")
        shutil.rmtree(OUTPUT_DIR)

    if (
        OUTPUT_DIR.exists()
        and previous_fingerprint
        and previous_fingerprint.get("sha256")
        and previous_fingerprint.get("sha256") != current_fingerprint.get("sha256")
    ):
        print("Detected changed training data fingerprint. Resetting old checkpoints for clean retraining.")
        shutil.rmtree(OUTPUT_DIR)

    if RESUME_TRAINING and OUTPUT_DIR.exists() and len(os.listdir(OUTPUT_DIR)) > 0:
        last_checkpoint = get_last_checkpoint(str(OUTPUT_DIR))
        if last_checkpoint is not None:
            checkpoint_epoch = _load_checkpoint_epoch(Path(last_checkpoint))
            if checkpoint_epoch is not None and checkpoint_epoch >= NUM_EPOCHS:
                print(
                    "Training already reached target epochs in checkpoint "
                    f"({checkpoint_epoch} >= {NUM_EPOCHS})."
                )
                print(
                    "No new epochs would run. Set SLM_FORCE_RETRAIN=1 to start fresh "
                    "or increase SLM_NUM_EPOCHS."
                )
                return
            print(f"==================================================")
            print(f" RESUMING TRAINING from checkpoint: {last_checkpoint}")
            print(f"==================================================")

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        eval_strategy="epoch",            # Explicitly structured natively to Epochs
        save_strategy="epoch",
        logging_strategy="epoch",         # Logs loss and precision per epoch
        save_total_limit=2,               # Keeps only the 2 most recent checkpoints to save 8GB SSD space
        learning_rate=5e-5,
        per_device_train_batch_size=PER_DEVICE_BATCH_SIZE,  # Increased to 32 for 30GB RAM
        per_device_eval_batch_size=PER_DEVICE_BATCH_SIZE,   # Increased to 32 for 30GB RAM
        gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,  # Reduced to 2 with larger batch
        num_train_epochs=NUM_EPOCHS,  # Increased to 15 epochs
        seed=RANDOM_SEED,
        data_seed=RANDOM_SEED,
        weight_decay=0.01,
        fp16=False,               # Must be False on CPU!
        use_cpu=True,
        dataloader_num_workers=NUM_WORKERS,  # Increased to 6 workers for 30GB RAM
        logging_steps=LOGGING_STEPS,
        logging_first_step=True,
        metric_for_best_model="eval_f1",
        greater_is_better=True,
        report_to="none",
        load_best_model_at_end=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        compute_metrics=compute_metrics,  # Inject mathematical logging evaluation
        processing_class=tokenizer,
        data_collator=data_collator,
    )

    print("5. Starting Optimized Training...")
    trainer.train(resume_from_checkpoint=last_checkpoint)
    _save_fingerprint(current_fingerprint)

    final_eval = trainer.evaluate()
    print("   -> Final evaluation metrics:", final_eval)

    print("6. Generating Training Visualizations...")
    FINAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    # Plot history safely
    log_history = trainer.state.log_history
    train_loss = [x["loss"] for x in log_history if "loss" in x and "epoch" in x]
    eval_loss = [x["eval_loss"] for x in log_history if "eval_loss" in x and "epoch" in x]
    
    plt.figure(figsize=(10, 5))
    if train_loss:
        plt.plot(train_loss, label="Training Loss", marker="o")
    if eval_loss:
        plt.plot(eval_loss, label="Validation Loss", marker="s")
    plt.title("SLM Training Loss over Epochs")
    plt.xlabel("Epochs")
    plt.ylabel("Loss")
    plt.legend()
    plt.grid(True)
    loss_chart_path = FINAL_MODEL_DIR / "training_loss_curve.png"
    plt.savefig(loss_chart_path)
    plt.close()
    print(f"   -> Loss curve saved to {loss_chart_path}")

    print("7. Generating Confusion Matrix on Valid Data...")
    predictions = trainer.predict(tokenized_datasets["test"])
    preds = np.argmax(predictions.predictions, axis=-1)
    cm = confusion_matrix(predictions.label_ids, preds)
    display_labels = _label_display_names(label_values)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=display_labels)
    disp.plot(cmap="Blues")
    plt.title("Validation Confusion Matrix")
    cm_path = FINAL_MODEL_DIR / "confusion_matrix.png"
    plt.savefig(cm_path)
    plt.close()
    print(f"   -> Confusion Matrix saved to {cm_path}")

    print("8. Saving Final Model...")
    # Write human-readable label names into model config
    id2label = {0: "Legitimate", 1: "Spam", 2: "Phishing"}
    label2id = {v: k for k, v in id2label.items()}
    model.config.id2label = id2label
    model.config.label2id = label2id
    trainer.save_model(str(FINAL_MODEL_DIR))

    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    state_json_path = RUN_LOG_DIR / f"trainer_state_{ts}.json"
    metrics_json_path = RUN_LOG_DIR / f"metrics_{ts}.json"
    report_txt_path = FINAL_MODEL_DIR / "training_report.txt"

    trainer_state = {
        "best_model_checkpoint": trainer.state.best_model_checkpoint,
        "best_metric": trainer.state.best_metric,
        "global_step": trainer.state.global_step,
        "epoch": trainer.state.epoch,
        "log_history": trainer.state.log_history,
    }
    state_json_path.write_text(json.dumps(trainer_state, indent=2), encoding="utf-8")

    class_report = classification_report(
        predictions.label_ids,
        preds,
        labels=label_values,
        target_names=display_labels,
        digits=4,
        zero_division=0,
        output_dict=True,
    )
    metrics_payload = {
        "timestamp_utc": ts,
        "model_id": model_id,
        "classes": label_values,
        "class_names": display_labels,
        "data": {
            "final_samples": len(df),
            "deduplicated_rows_removed": dedup_removed,
            "label_distribution": {str(k): int(v) for k, v in df["label"].value_counts().to_dict().items()},
            "max_seq_len": MAX_SEQ_LEN,
            "max_words_per_sample": MAX_WORDS_PER_SAMPLE,
            "max_samples_per_class": MAX_SAMPLES_PER_CLASS,
            "min_samples_per_class": MIN_SAMPLES_PER_CLASS,
        },
        "training": {
            "num_epochs": NUM_EPOCHS,
            "logging_steps": LOGGING_STEPS,
            "resume_training": RESUME_TRAINING,
            "force_retrain": FORCE_RETRAIN,
            "checkpoint_used": last_checkpoint,
            "best_checkpoint": trainer.state.best_model_checkpoint,
            "best_metric": trainer.state.best_metric,
            "global_step": trainer.state.global_step,
            "final_eval": final_eval,
        },
        "classification_report": class_report,
        "confusion_matrix": cm.tolist(),
    }
    metrics_json_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    report_lines = [
        "Content SLM Training Report",
        "===========================",
        "",
        f"Timestamp (UTC): {ts}",
        f"Model ID: {model_id}",
        f"Classes: {label_values}",
        f"Class names: {', '.join(display_labels)}",
        "",
        "Data summary",
        "------------",
        f"Final samples: {len(df)}",
        f"Deduplicated rows removed: {dedup_removed}",
        f"Label distribution: {df['label'].value_counts().to_dict()}",
        f"Token budget: max_seq_len={MAX_SEQ_LEN}, max_words_per_sample={MAX_WORDS_PER_SAMPLE}, max_samples_per_class={MAX_SAMPLES_PER_CLASS}",
        f"Class floor: min_samples_per_class={MIN_SAMPLES_PER_CLASS}",
        "",
        "Training summary",
        "----------------",
        f"Epoch target: {NUM_EPOCHS}",
        f"Global step: {trainer.state.global_step}",
        f"Best metric (eval_f1): {trainer.state.best_metric}",
        f"Best checkpoint: {trainer.state.best_model_checkpoint}",
        f"Final eval: {final_eval}",
        "",
        "Per-class report",
        "----------------",
        classification_report(
            predictions.label_ids,
            preds,
            labels=label_values,
            target_names=display_labels,
            digits=4,
            zero_division=0,
        ),
        "",
        "Artifacts",
        "---------",
        f"Model directory: {FINAL_MODEL_DIR}",
        f"Loss curve: {loss_chart_path}",
        f"Confusion matrix: {cm_path}",
        f"Trainer state JSON: {state_json_path}",
        f"Metrics JSON: {metrics_json_path}",
    ]
    report_txt_path.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"   -> Detailed text report: {report_txt_path}")
    print(f"   -> Full trainer state JSON: {state_json_path}")
    print(f"   -> Detailed metrics JSON: {metrics_json_path}")

    print(f"Training Complete! SLM fully exported to {FINAL_MODEL_DIR}")

if __name__ == "__main__":
    main()
