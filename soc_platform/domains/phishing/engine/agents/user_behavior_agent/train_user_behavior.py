"""
XGBoost ML Pipeline for User Behavior Agent.
Trains the contextual vulnerability model on the corporate social graph simulation.
"""
from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import json
from pathlib import Path
from datetime import datetime
import warnings

import pandas as pd
import numpy as np
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    roc_auc_score, brier_score_loss, confusion_matrix, roc_curve,
    accuracy_score, precision_score, recall_score, f1_score, average_precision_score,
    PrecisionRecallDisplay, RocCurveDisplay
)
from sklearn.model_selection import train_test_split

# Supress matplotlib GUI warnings in headless execution
import matplotlib
matplotlib.use('Agg')

try:
    from soc_platform.domains.phishing.engine.configs.settings import PROJECT_ROOT
except ImportError:
    PROJECT_ROOT = PHISHING_HOME
# Path Configuration
MODEL_DIR = (PROJECT_ROOT / ".." / "models" / "user_behavior_agent").resolve()
REPORT_DIR = PROJECT_ROOT / "analysis_reports" / f"user_behavior_train_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
DATA_FILE = (PROJECT_ROOT / ".." / "datasets_processed" / "user_behavior" / "user_behavior_training.csv").resolve()

def run_training():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading data from {DATA_FILE}")
    df = pd.read_csv(DATA_FILE)
    
    # 1. Exploratory Data Analysis (EDA) Visuals
    print("Generating EDA Visuals...")
    plt.figure(figsize=(10, 8))
    sns.heatmap(df.corr(), annot=True, cmap="coolwarm", fmt=".2f")
    plt.title("User Behavior Feature Correlative Heatmap")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "eda_correlation.png")
    plt.close()

    plt.figure(figsize=(8, 6))
    sns.boxplot(x="label", y="days_since_last_contact", data=df)
    plt.title("Days Since Last Contact over Class Variation")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "eda_contact_anomaly.png")
    plt.close()

    # 2. Train/Test Split
    X = df.drop(columns=["label"])
    y = df["label"]
    
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.15, stratify=y_train, random_state=42)

    # 3. Model Architecture
    xgb_params = {
        "objective": "binary:logistic",
        "eval_metric": ["logloss", "auc"],
        "max_depth": 5,
        "learning_rate": 0.05,
        "n_estimators": 500,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "tree_method": "hist", # Faster approximation
        "scale_pos_weight": float(np.sum(y_train == 0) / np.sum(y_train == 1)), # Balancing heavily Benign dataset
        "early_stopping_rounds": 25,
    }

    model = xgb.XGBClassifier(**xgb_params)
    
    print("Training XGBoost...")
    model.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_val, y_val)],
        verbose=False
    )

    # 4. Metrics & Diagnostics
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, probs)
    brier = brier_score_loss(y_test, probs)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    pr_auc = average_precision_score(y_test, probs)
    
    best_iteration = model.best_iteration

    print(f"\n--- Detailed Results ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC AUC:   {roc_auc:.4f}")
    print(f"PR AUC:    {pr_auc:.4f}")
    print(f"Brier:     {brier:.4f}")
    print(f"Best Iter: {best_iteration}")

    # Generate Learning Curves
    results = model.evals_result()
    plt.figure(figsize=(10, 6))
    plt.plot(results["validation_0"]["logloss"], label="Train LogLoss")
    plt.plot(results["validation_1"]["logloss"], label="Val LogLoss")
    plt.axvline(best_iteration, color="red", linestyle="--", label="Early Stopping")
    plt.legend()
    plt.title("XGBoost Convergence & Early Stopping")
    plt.savefig(REPORT_DIR / "learning_curve_logloss.png")
    plt.close()

    # Generate Importance
    plt.figure(figsize=(10, 6))
    xgb.plot_importance(model, max_num_features=10, grid=False)
    plt.title("XGBoost Inherent Feature Relevance")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "feature_importance.png")
    plt.close()

    # Confusion Matrix
    cm = confusion_matrix(y_test, preds)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Testing Confusion Matrix (Class Segregation)")
    plt.ylabel("True Class")
    plt.xlabel("Predicted Class")
    plt.tight_layout()
    plt.savefig(REPORT_DIR / "confusion_matrix.png")
    plt.close()
    
    # ROC Curve
    plt.figure(figsize=(8, 6))
    RocCurveDisplay.from_predictions(y_test, probs)
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.savefig(REPORT_DIR / "roc_curve.png")
    plt.close()

    # Precision-Recall Curve
    plt.figure(figsize=(8, 6))
    PrecisionRecallDisplay.from_predictions(y_test, probs)
    plt.title("Precision-Recall (PR) Curve")
    plt.savefig(REPORT_DIR / "pr_curve.png")
    plt.close()

    # Probability Density
    plt.figure(figsize=(8, 6))
    sns.kdeplot(probs[y_test == 0], label="Benign (Class 0)", shade=True, color="blue")
    sns.kdeplot(probs[y_test == 1], label="Anomalous (Class 1)", shade=True, color="red")
    plt.title("Model Prediction Probability Density")
    plt.xlabel("Predicted Probability")
    plt.ylabel("Density")
    plt.legend()
    plt.savefig(REPORT_DIR / "probability_density.png")
    plt.close()
    
    # Save Model
    out_file = MODEL_DIR / "user_behavior_xgb.json"
    model.save_model(str(out_file))
    print(f"Model serialized strictly to: {out_file}")

    # Save Metrics Manifest
    payload = {
        "training_time_utc": datetime.utcnow().isoformat(),
        "test_n": len(y_test),
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "brier_score": brier
        },
        "best_iteration": best_iteration,
        "features": feature_names
    }
    with open(REPORT_DIR / "metrics.json", "w") as f:
        json.dump(payload, f, indent=4)

if __name__ == "__main__":
    warnings.filterwarnings('ignore')
    run_training()
