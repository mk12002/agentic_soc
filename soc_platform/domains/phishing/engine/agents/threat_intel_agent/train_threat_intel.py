"""
Threat Intelligence Agent - XGBoost Training Pipeline

This script trains the message-level risk scoring model using the synthetic 
dataset generated in the previous phase. It uses XGBoost, saves the model 
for production inference, and generates detailed visualizations (feature 
importance, ROC, learning curves, correlation).
"""

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    roc_auc_score,
    roc_curve,
    brier_score_loss,
    confusion_matrix,
    classification_report
)

from soc_platform.domains.phishing.engine.preprocessing.threat_intel_feature_contract import MESSAGE_FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
try:
    from soc_platform.domains.phishing.engine.configs.settings import PROJECT_ROOT
except ImportError:
    PROJECT_ROOT = PHISHING_HOME
DATA_DIR = PROJECT_ROOT / "datasets_processed" / "threat_intel"
# We save models in the root 'models/' directory alongside other agents
MODEL_DIR = (PROJECT_ROOT / ".." / "models" / "threat_intel_agent").resolve()
REPORT_DIR = PROJECT_ROOT / "analysis_reports" / f"threat_intel_train_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def load_dataset(split: str) -> pd.DataFrame:
    """Load a specific split of the dataset."""
    path = DATA_DIR / f"threat_intel_{split}.csv"
    if not path.exists():
        raise FileNotFoundError(f"Dataset {path} not found. Run preprocessing first.")
    return pd.read_csv(path)


def plot_correlation_matrix(df: pd.DataFrame, out_path: Path):
    """Save feature correlation heatmap."""
    plt.figure(figsize=(12, 10))
    corr = df[MESSAGE_FEATURE_COLUMNS].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    sns.heatmap(corr, mask=mask, annot=True, fmt=".2f", cmap="coolwarm", center=0,
                square=True, linewidths=.5, cbar_kws={"shrink": .5})
    plt.title("Feature Correlation Matrix")
    plt.tight_layout()
    plt.savefig(out_path / "correlation_matrix.png", dpi=150)
    plt.close()


def plot_roc_curve(y_true, y_prob, out_path: Path):
    """Save ROC AUC curve."""
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    auc_score = roc_auc_score(y_true, y_prob)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {auc_score:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.savefig(out_path / "roc_curve.png", dpi=150)
    plt.close()


def plot_confusion_matrix(y_true, y_pred, out_path: Path):
    """Save Confusion Matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Benign (0)", "Malicious (1)"],
                yticklabels=["Benign (0)", "Malicious (1)"])
    plt.title("Confusion Matrix")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(out_path / "confusion_matrix.png", dpi=150)
    plt.close()


def plot_feature_importance(model: xgb.XGBClassifier, out_path: Path):
    """Save XGBoost Feature Importance plot."""
    plt.figure(figsize=(10, 8))
    # Use gained importance
    importance = model.get_booster().get_score(importance_type='gain')
    if not importance:
        return
        
    df_imp = pd.DataFrame(list(importance.items()), columns=['Feature', 'Gain'])
    df_imp = df_imp.sort_values(by='Gain', ascending=True)

    plt.barh(df_imp['Feature'], df_imp['Gain'], color='skyblue')
    plt.xlabel('F-Score (Gain)')
    plt.title('XGBoost Feature Importance')
    plt.tight_layout()
    plt.savefig(out_path / "feature_importance.png", dpi=150)
    plt.close()


def plot_learning_curves(evals_result: dict, out_path: Path):
    """Save learning curves from evals_result to check for overfitting."""
    if not evals_result:
        return
    
    epochs = len(evals_result['validation_0']['logloss'])
    x_axis = range(0, epochs)
    
    plt.figure(figsize=(8, 5))
    plt.plot(x_axis, evals_result['validation_0']['logloss'], label='Train')
    plt.plot(x_axis, evals_result['validation_1']['logloss'], label='Test/Val')
    plt.legend()
    plt.ylabel('Log Loss')
    plt.xlabel('Epochs')
    plt.title('XGBoost Learning Curve (LogLoss)')
    plt.grid(True, alpha=0.3)
    plt.savefig(out_path / "learning_curve_logloss.png", dpi=150)
    plt.close()


def train_model():
    """Execute the full XGBoost training pipeline."""
    print(f"Loading datasets from {DATA_DIR}...")
    df_train = load_dataset("train")
    df_val = load_dataset("val")
    df_test = load_dataset("test")

    X_train = df_train[MESSAGE_FEATURE_COLUMNS]
    y_train = df_train["label"]
    w_train = df_train["label_confidence"]  # Use confidence for sample weighting!

    X_val = df_val[MESSAGE_FEATURE_COLUMNS]
    y_val = df_val["label"]

    X_test = df_test[MESSAGE_FEATURE_COLUMNS]
    y_test = df_test["label"]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating exploratory data visualizations...")
    plot_correlation_matrix(df_train, REPORT_DIR)

    print("Initializing XGBoost Classifier...")
    # Production-tuned hyperparameters for structured tabular security data
    params = {
        "n_estimators": 500,
        "learning_rate": 0.05,
        "max_depth": 5,
        "min_child_weight": 2,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "objective": "binary:logistic",
        "eval_metric": ["logloss", "auc"],
        "early_stopping_rounds": 40,
        "random_state": 42,
        "n_jobs": -1
    }
    
    model = xgb.XGBClassifier(**params)

    print("Starting model training (with early stopping)...")
    model.fit(
        X_train, y_train, 
        sample_weight=w_train,
        eval_set=[(X_train, y_train), (X_val, y_val)],
        verbose=False
    )
    
    print(f"Training stopped at iteration {model.best_iteration} with {model.best_score} score.")

    # Generate test metrics
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = model.predict(X_test)

    auc = roc_auc_score(y_test, y_prob)
    brier = brier_score_loss(y_test, y_prob)

    print("\n--- FINAL TEST SET METRICS ---")
    print(f"ROC AUC Score: {auc:.4f}")
    print(f"Brier Score (Calibration): {brier:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Save visual reports
    print(f"Saving visual reports to {REPORT_DIR}...")
    plot_roc_curve(y_test, y_prob, REPORT_DIR)
    plot_confusion_matrix(y_test, y_pred, REPORT_DIR)
    plot_feature_importance(model, REPORT_DIR)
    plot_learning_curves(model.evals_result(), REPORT_DIR)

    # Save detailed metrics to JSON
    metrics = {
        "training_time_utc": datetime.utcnow().isoformat(),
        "test_n": len(y_test),
        "roc_auc": float(auc),
        "brier_score": float(brier),
        "best_iteration": int(model.best_iteration),
        "best_score_val_auc": float(model.evals_result()['validation_1']['auc'][model.best_iteration]),
        "features": MESSAGE_FEATURE_COLUMNS,
    }
    with open(REPORT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)

    # Save the model artifact
    model_path = MODEL_DIR / "threat_intel_xgb.json"
    model.save_model(str(model_path))
    print(f"Model saved successfully to {model_path}")
    print(f"Training complete. Reports are strictly contained in {REPORT_DIR.name}.")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')
    train_model()
