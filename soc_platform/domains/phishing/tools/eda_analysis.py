"""
Exploratory Data Analysis (EDA) for Processed Email Security Datasets.
Generates statistical summaries and Matplotlib visualizations for all training datasets.
"""

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import os
from pathlib import Path
import warnings

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

REPO_ROOT = PHISHING_HOME
PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
EMBER_DIR = REPO_ROOT.parent / "datasets" / "attachments" / "malware" / "ember_features"
ANALYSIS_DIR = REPO_ROOT / "analysis_reports"

ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

def analyze_url_dataset():
    print("\n--- Analyzing URL Dataset ---")
    csv_path = PROCESSED_DIR / "url_training.csv"
    if not csv_path.exists():
        print("URL dataset not found.")
        return
    
    df = pd.read_csv(csv_path)
    print(f"Total URL Samples: {len(df):,}")
    print(f"Missing Values:\n{df.isnull().sum()}")
    
    # Class Balance Plot
    plt.figure(figsize=(8, 5))
    counts = df["label"].value_counts()
    counts.plot(kind="bar", color=["#4CAF50", "#F44336"])
    plt.title("URL Dataset: Class Balance (1=Malicious, 0=Benign)")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(ANALYSIS_DIR / "url_class_balance.png")
    plt.close()
    
    # Feature Distributions
    features = ["url_length", "subdomain_count", "special_char_count", "host_entropy"]
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.flatten()
    
    for i, feature in enumerate(features):
        if feature in df.columns:
            # Drop upper outliers for better visualization
            q99 = df[feature].quantile(0.99)
            filtered = df[df[feature] <= q99]
            
            axes[i].hist(filtered[filtered["label"] == 0][feature], bins=50, alpha=0.5, label="Benign", color="green")
            axes[i].hist(filtered[filtered["label"] == 1][feature], bins=50, alpha=0.5, label="Malicious", color="red")
            axes[i].set_title(f"Distribution: {feature}")
            axes[i].legend()
            
    plt.tight_layout()
    plt.savefig(ANALYSIS_DIR / "url_feature_distributions.png")
    plt.close()
    print(f"Saved URL analysis plots to {ANALYSIS_DIR}")


def analyze_content_dataset():
    print("\n--- Analyzing Content Dataset ---")
    csv_path = PROCESSED_DIR / "content_training.csv"
    if not csv_path.exists():
        print("Content dataset not found.")
        return
    
    df = pd.read_csv(csv_path)
    print(f"Total Content Samples: {len(df):,}")
    print(f"Missing Values:\n{df.isnull().sum()}")
    
    # Class Balance
    plt.figure(figsize=(8, 5))
    counts = df["label"].value_counts()
    counts.plot(kind="bar", color=["#4CAF50", "#FF9800", "#F44336"][:len(counts)])
    plt.title("Content Dataset: Class Balance (0=Legit, 1=Spam, 2=Phish)")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(ANALYSIS_DIR / "content_class_balance.png")
    plt.close()
    
    # Text Length Analysis
    df["text_length"] = df["text"].astype(str).apply(len)
    df["word_count"] = df["text"].astype(str).apply(lambda x: len(x.split()))
    
    print("\nText Length Statistics:")
    print(df.groupby("label")[["text_length", "word_count"]].describe())
    
    plt.figure(figsize=(10, 6))
    # Plot word count up to 95th percentile
    q95 = df["word_count"].quantile(0.95)
    filtered = df[df["word_count"] <= q95]
    
    plt.hist(filtered[filtered["label"] == 0]["word_count"], bins=50, alpha=0.5, label="Legit", color="green")
    if 1 in filtered["label"].values:
        plt.hist(filtered[filtered["label"] == 1]["word_count"], bins=50, alpha=0.5, label="Spam", color="orange")
    if 2 in filtered["label"].values:
        plt.hist(filtered[filtered["label"] == 2]["word_count"], bins=50, alpha=0.5, label="Phishing", color="red")
    plt.title("Word Count Distribution (Truncated at 95th percentile)")
    plt.xlabel("Number of Words")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.savefig(ANALYSIS_DIR / "content_word_count.png")
    plt.close()
    print(f"Saved Content analysis plots to {ANALYSIS_DIR}")


def analyze_ember_dataset():
    print("\n--- Analyzing EMBER Attachment Dataset ---")
    parquet_path = EMBER_DIR / "train_ember_2018_v2_features.parquet"
    if not parquet_path.exists():
        print("EMBER dataset not found.")
        return
        
    print(f"Loading massive Parquet file {parquet_path.name}...")
    df = pd.read_parquet(parquet_path)
    
    print(f"Total Malware/Benign Samples: {len(df):,}")
    print(f"Total Feature Dimensions: {df.shape[1] - 1}") # Subtract label
    print(f"Memory Usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    # Class Balance Plot
    plt.figure(figsize=(8, 5))
    counts = df["label"].value_counts()
    counts.plot(kind="bar", color=["#4CAF50", "#F44336"])
    plt.title("EMBER Attachment Dataset: Class Balance (1=Malware, 0=Benign)")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(ANALYSIS_DIR / "ember_class_balance.png")
    plt.close()
    print(f"Saved EMBER analysis plots to {ANALYSIS_DIR}")


def analyze_small_datasets():
    print("\n--- Analyzing Header Dataset ---")
    for name in ["header"]:
        csv_path = PROCESSED_DIR / f"{name}_training.csv"
        if not csv_path.exists():
            continue
            
        df = pd.read_csv(csv_path)
        print(f"\n{name.capitalize()} Data Samples: {len(df)}")
        print(df.head())
        
        plt.figure(figsize=(8, 5))
        counts = df["label" if "label" in df.columns else df.columns[-1]].value_counts()
        counts.plot(kind="bar", color=["#2196F3", "#FF9800"])
        plt.title(f"{name.capitalize()} Dataset: Label Distribution")
        plt.tight_layout()
        plt.savefig(ANALYSIS_DIR / f"{name}_class_balance.png")
        plt.close()


if __name__ == "__main__":
    print("=============================================")
    print("       STARTING DATASET EDA ANALYSIS         ")
    print("=============================================")
    analyze_url_dataset()
    analyze_content_dataset()
    analyze_ember_dataset()
    analyze_small_datasets()
    print("\nEDA Complete! Check the 'analysis_reports' folder for visualization plots.")
