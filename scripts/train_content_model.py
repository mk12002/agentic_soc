"""Train the phishing content model from public data, evaluate it, and write it with a model card.

    python scripts/train_content_model.py --data DIR [--download] [--variant compact|large] [--out DIR]
                                          [--compare-transformer DIR] [--write]

Data (downloaded into DIR with --download, never into the repository):
- phishing: the Nazario phishing corpus 2019-2025 (CC BY 4.0, https://monkey.org/~jose/phishing/) - real phishing
- spam and legitimate mail: the SpamAssassin public corpus (https://spamassassin.apache.org/old/publiccorpus/;
  terms: non-live testing only - the messages are never sent anywhere)
- more legitimate mail: the "Safe Email" rows of zefang-liu/phishing-email-dataset (LGPL-3.0, Hugging Face). Its
  "Phishing Email" rows are left out: most of them are ordinary spam, which would teach "spam = phishing".

Model: TF-IDF text features + logistic regression, three classes (legitimate, spam, phishing). The text is prepared
by ``content_agent.text_prep.normalize`` - the same function the agent uses at inference. Evaluation: a stratified
20 % hold-out (after de-duplication) and the platform's own labelled corpus, which is never trained on. With
--compare-transformer the current transformer is scored on exactly the same messages. --write replaces the model
files in --out only when asked; the choice to replace is made from the printed comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import random
import tarfile
import time
import urllib.request
from email import message_from_bytes, policy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = ["Legitimate", "Spam", "Phishing"]            # class index = position; the agent reads proba[-1] as phishing
SPAMASSASSIN = "https://spamassassin.apache.org/old/publiccorpus/"
SA_FILES = {"20030228_easy_ham.tar.bz2": 0, "20030228_easy_ham_2.tar.bz2": 0, "20030228_hard_ham.tar.bz2": 0,
            "20030228_spam.tar.bz2": 1, "20050311_spam_2.tar.bz2": 1}
NAZARIO = "https://monkey.org/~jose/phishing/"
NAZARIO_YEARS = range(2019, 2026)
HF_CSV = "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv"
SOURCES = [
    {"name": "Nazario phishing corpus 2019-2025", "url": NAZARIO, "licence": "CC BY 4.0",
     "attribution": "Phishing corpus by Jose Nazario, https://monkey.org/~jose/phishing/, CC BY 4.0", "class": "Phishing"},
    {"name": "SpamAssassin public corpus", "url": SPAMASSASSIN, "licence": "non-live testing only (messages never sent)",
     "class": "Legitimate (ham) and Spam"},
    {"name": "zefang-liu/phishing-email-dataset, Safe Email rows", "url": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset",
     "licence": "LGPL-3.0", "class": "Legitimate"},
]


def download(data: Path) -> None:
    data.mkdir(parents=True, exist_ok=True)
    targets = {**{f: SPAMASSASSIN + f for f in SA_FILES}, **{f"phishing-{y}": f"{NAZARIO}phishing-{y}" for y in NAZARIO_YEARS},
               "Phishing_Email.csv": HF_CSV, "NAZARIO_LICENSE.txt": NAZARIO + "LICENSE.txt"}
    for name, url in targets.items():
        if not (data / name).exists():
            print("downloading", url)
            urllib.request.urlretrieve(url, data / name)  # nosec B310 - fixed https dataset URLs
    for name in SA_FILES:
        with tarfile.open(data / name) as tar:
            tar.extractall(data, filter="data")


def parts(msg) -> str:
    """Subject + plain text + HTML, as the engine's content feature extractor builds its text."""
    subject = str(msg.get("subject", "") or "")
    plain, html = [], []
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except (LookupError, AssertionError):
            continue
        (plain if ctype == "text/plain" else html).append(text)
    return f"{subject}\n{' '.join(plain)}\n{' '.join(html)}".strip()


def load(data: Path, seed: int, hf_safe: int) -> tuple[list[str], list[int], list[str]]:
    texts, labels, sources = [], [], []
    for name, label in SA_FILES.items():
        folder = data / name.split("_", 1)[1].replace(".tar.bz2", "")
        for f in sorted(folder.glob("*")):
            if f.name == "cmds":
                continue
            texts.append(parts(message_from_bytes(f.read_bytes(), policy=policy.compat32)))
            labels.append(label)
            sources.append("spamassassin")
    for y in NAZARIO_YEARS:
        for msg in mailbox.mbox(str(data / f"phishing-{y}")):
            texts.append(parts(msg))
            labels.append(2)
            sources.append(f"nazario-{y}")
    import pandas as pd

    df = pd.read_csv(data / "Phishing_Email.csv")
    safe = df[df["Email Type"] == "Safe Email"]["Email Text"].dropna().astype(str).tolist()
    random.Random(seed).shuffle(safe)
    for t in safe[:hf_safe]:
        texts.append(t)
        labels.append(0)
        sources.append("hf-safe")
    return texts, labels, sources


def corpus() -> tuple[list[str], list[int], list[str]]:
    """The platform's labelled corpus, text built exactly as the engine builds it at inference."""
    from soc_platform.domains.phishing.agents.analyzer import EngineAnalyzer
    from soc_platform.domains.phishing.engine.agents.content_agent.feature_extractor import extract_features

    e = EngineAnalyzer()
    e._load()
    target = {"malicious": 2, "suspicious": 2, "spam": 1, "safe": 0}
    texts, labels, names = [], [], []
    for d in [ROOT / "artifacts" / "phishing" / "corpus"]:
        for name, lbl in json.loads((d / "labels.json").read_text()).items():
            payload = e.parser.parse_file(str(d / f"{name}.eml"))
            texts.append(extract_features(payload)["text"])
            labels.append(target[lbl])
            names.append(name)
    return texts, labels, names


def report(y_true, y_pred, title: str) -> dict:
    from sklearn.metrics import classification_report, confusion_matrix

    r = classification_report(y_true, y_pred, labels=[0, 1, 2], target_names=LABELS, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist()
    print(f"\n== {title} ==")
    for c in LABELS:
        print(f"  {c:11} precision {r[c]['precision']:.3f}  recall {r[c]['recall']:.3f}  n={int(r[c]['support'])}")
    print(f"  macro F1 {r['macro avg']['f1-score']:.3f}   accuracy {r['accuracy']:.3f}   confusion (rows=truth) {cm}")
    return {"per_class": {c: {k: round(r[c][k], 4) for k in ("precision", "recall", "f1-score", "support")} for c in LABELS},
            "macro_f1": round(r["macro avg"]["f1-score"], 4), "accuracy": round(r["accuracy"], 4), "confusion": cm}


def build(variant: str):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion

    from soc_platform.domains.phishing.engine.agents.content_agent.text_prep import normalize

    word = TfidfVectorizer(preprocessor=normalize, ngram_range=(1, 2), min_df=3, max_df=0.9, sublinear_tf=True,
                           max_features=60_000 if variant == "compact" else 150_000, dtype=__import__("numpy").float32)
    if variant == "compact":
        vec = word
    else:
        char = TfidfVectorizer(preprocessor=normalize, analyzer="char_wb", ngram_range=(3, 5), min_df=5, max_df=0.9,
                               sublinear_tf=True, max_features=150_000, dtype=__import__("numpy").float32)
        vec = FeatureUnion([("word", word), ("char", char)])
    clf = LogisticRegression(C=8.0, max_iter=4000, class_weight="balanced")
    return vec, clf


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--variant", choices=["compact", "large"], default="compact")
    ap.add_argument("--out", default=str(ROOT / "artifacts" / "phishing" / "models" / "content_agent"))
    ap.add_argument("--compare-transformer", default=None, help="directory of the current transformer to score too")
    ap.add_argument("--hf-safe", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--write", action="store_true", help="write model.joblib + model_card.json into --out")
    a = ap.parse_args()

    import joblib
    from sklearn.model_selection import train_test_split

    from soc_platform.domains.phishing.engine.agents.content_agent.text_prep import normalize

    data = Path(a.data)
    if a.download:
        download(data)
    texts, labels, sources = load(data, a.seed, a.hf_safe)
    seen, X, y, src = set(), [], [], []
    for t, lbl, s in zip(texts, labels, sources, strict=True):     # de-duplicate on the text the model sees
        key = hashlib.sha1(normalize(t).encode(), usedforsecurity=False).hexdigest()
        if key in seen or len(normalize(t)) < 20:
            continue
        seen.add(key)
        X.append(t)
        y.append(lbl)
        src.append(s)
    counts = {LABELS[c]: y.count(c) for c in range(3)}
    print("messages after de-duplication:", len(X), counts)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=a.seed)
    vec, clf = build(a.variant)
    t0 = time.time()
    clf.fit(vec.fit_transform(Xtr), ytr)
    print(f"trained {a.variant} in {time.time() - t0:.0f} s")
    held = report(yte, clf.predict(vec.transform(Xte)), f"hold-out ({len(Xte)} messages) - new {a.variant} model")
    ctexts, clabels, cnames = corpus()
    cpred = clf.predict(vec.transform(ctexts))
    corp = report(clabels, cpred, "platform corpus (never trained on) - new model")
    for n, t, p in zip(cnames, clabels, cpred, strict=True):
        print(f"    {n:28} truth={LABELS[t]:10} new={LABELS[p]}")
    out = {"variant": a.variant, "trained_at": time.strftime("%Y-%m-%d"), "labels": LABELS, "sources": SOURCES,
           "training_messages": len(Xtr), "class_counts": counts, "holdout": held, "platform_corpus": corp}

    if a.compare_transformer:
        from transformers import pipeline

        pipe = pipeline("text-classification", model=a.compare_transformer, tokenizer=a.compare_transformer,
                        truncation=True, local_files_only=True)
        idx = {lbl: i for i, lbl in enumerate(LABELS)}
        from soc_platform.domains.phishing.engine.agents.content_agent.inference import _compact_text

        def tpred(ts):
            return [idx[pipe(_compact_text(t), truncation=True, max_length=128)[0]["label"]] for t in ts]

        sample = list(range(len(Xte)))
        random.Random(a.seed).shuffle(sample)
        sample = sample[:2000]
        out["transformer_holdout"] = report([yte[i] for i in sample], tpred([Xte[i] for i in sample]),
                                            "hold-out sample (2,000) - current transformer")
        out["new_on_same_sample"] = report([yte[i] for i in sample], clf.predict(vec.transform([Xte[i] for i in sample])),
                                           "hold-out sample (2,000) - new model")
        tp = tpred(ctexts)
        out["transformer_corpus"] = report(clabels, tp, "platform corpus - current transformer")
        for n, t, p in zip(cnames, clabels, tp, strict=True):
            print(f"    {n:28} truth={LABELS[t]:10} transformer={LABELS[p]}")

    if a.write:
        dst = Path(a.out)
        clf.fit(vec.fit_transform(X), y)                          # final model on all the data, same settings
        bundle = {"kind": "sklearn_bundle", "model": clf, "vectorizer": vec, "labels": LABELS,
                  "risk_by_label": {"Legitimate": 0.0, "Spam": 0.65, "Phishing": 0.95}, "card": out}
        joblib.dump(bundle, dst / "model.joblib", compress=3)
        (dst / "model_card.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
        print(f"\nwrote {dst / 'model.joblib'} ({(dst / 'model.joblib').stat().st_size / 1e6:.1f} MB) and model_card.json")
    else:
        print("\n(not written: add --write to replace the model)")


if __name__ == "__main__":
    main()
