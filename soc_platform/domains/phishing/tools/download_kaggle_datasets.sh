#!/bin/bash

set -uo pipefail

# Target directory for datasets
BASE_DIR=${1:-"/home/LabsKraft/new_work/datasets"}
KAGGLE_BIN=${KAGGLE_BIN:-"$HOME/.local/bin/kaggle"}

# Sandbox behavior dataset references (override through env if needed).
OLIVEIRA_DATASET_REF=${OLIVEIRA_DATASET_REF:-""}
CUCKOO_DATASET_REF=${CUCKOO_DATASET_REF:-""}
CUCKOO_REPORTS_URL=${CUCKOO_REPORTS_URL:-""}

FAILED_DOWNLOADS=0

run_download() {
    local description="$1"
    shift
    echo "$description"
    if "$@"; then
        return 0
    fi
    echo "WARNING: Failed -> $description"
    FAILED_DOWNLOADS=$((FAILED_DOWNLOADS + 1))
    return 1
}

echo "Checking for Kaggle API credentials..."
if [ ! -f ~/.kaggle/kaggle.json ]; then
    echo "ERROR: ~/.kaggle/kaggle.json is missing!"
    echo "Please insert your Kaggle API key following the instructions provided, then re-run this script."
    exit 1
fi

echo "Downloading Missing Kaggle Datasets into $BASE_DIR..."

if [ ! -x "$KAGGLE_BIN" ]; then
    echo "ERROR: Kaggle CLI not found at $KAGGLE_BIN"
    echo "Set KAGGLE_BIN or install with: pip install kaggle"
    exit 1
fi

# CEAS 2008 Spam
if [ -z "$(ls -A "$BASE_DIR"/email_content/spam/ceas2008 2>/dev/null)" ]; then
    echo "Downloading CEAS 2008 Spam..."
    run_download "Downloading CEAS 2008 Spam..." \
        "$KAGGLE_BIN" datasets download -d bayes2003/emails-for-spam-or-ham-classification -p "$BASE_DIR/email_content/spam/ceas2008/" --unzip
else
    echo "CEAS 2008 Spam already exists. Skipping."
fi

# Ling-Spam
if [ -z "$(ls -A "$BASE_DIR"/email_content/spam/ling_spam 2>/dev/null)" ]; then
    echo "Downloading Ling-Spam..."
    run_download "Downloading Ling-Spam..." \
        "$KAGGLE_BIN" datasets download -d mandygu/lingspam-dataset -p "$BASE_DIR/email_content/spam/ling_spam/" --unzip
else
    echo "Ling-Spam already exists. Skipping."
fi

# Nigerian Fraud Corpus
if [ -z "$(ls -A "$BASE_DIR"/email_content/phishing/nigerian_fraud 2>/dev/null)" ]; then
    echo "Downloading Nigerian Fraud Corpus..."
    run_download "Downloading Nigerian Fraud Corpus..." \
        "$KAGGLE_BIN" datasets download -d rtatman/fraudulent-email-corpus -p "$BASE_DIR/email_content/phishing/nigerian_fraud/" --unzip
else
    echo "Nigerian Fraud Corpus already exists. Skipping."
fi

# Phishing Email Dataset (Kaggle)
if [ -z "$(ls -A "$BASE_DIR"/email_content/phishing/kaggle_phishing 2>/dev/null)" ]; then
    echo "Downloading Phishing Email Dataset..."
    run_download "Downloading Phishing Email Dataset..." \
        "$KAGGLE_BIN" datasets download -d naserabdullahalam/phishing-email-dataset -p "$BASE_DIR/email_content/phishing/kaggle_phishing/" --unzip
else
    echo "Phishing Email Dataset already exists. Skipping."
fi

# Kaggle Malicious URLs (651K URLs)
if [ ! -f "$BASE_DIR/url_dataset/malicious_phish.csv" ]; then
    echo "Downloading Kaggle Malicious URLs..."
    run_download "Downloading Kaggle Malicious URLs..." \
        "$KAGGLE_BIN" datasets download -d sid321axn/malicious-urls-dataset -p "$BASE_DIR/url_dataset/" --unzip
else
    echo "Kaggle Malicious URLs already exist. Skipping."
fi

# Enron
if [ ! -f "$BASE_DIR/email_content/legitimate/enron/emails.csv" ]; then
    echo "Downloading Enron Email Dataset..."
    run_download "Downloading Enron Email Dataset..." \
        "$KAGGLE_BIN" datasets download -d wcukierski/enron-email-dataset -p "$BASE_DIR/email_content/legitimate/enron/" --unzip
else
    echo "Enron Email Dataset already exists. Skipping."
fi

# Sandbox API Call Sequences (Oliveira / malware-analysis style datasets)
mkdir -p "$BASE_DIR/sandbox_behavior/api_sequences"
if [ -z "$(ls -A "$BASE_DIR"/sandbox_behavior/api_sequences 2>/dev/null)" ]; then
    if [ -n "$OLIVEIRA_DATASET_REF" ]; then
        echo "Downloading Oliveira-style API call sequence dataset..."
        run_download "Downloading Oliveira-style API call sequence dataset..." \
            "$KAGGLE_BIN" datasets download -d "$OLIVEIRA_DATASET_REF" -p "$BASE_DIR/sandbox_behavior/api_sequences/" --unzip
    else
        echo "Skipping API call sequence dataset. Set OLIVEIRA_DATASET_REF=<owner/dataset>."
    fi
else
    echo "Sandbox API sequence data already exists. Skipping."
fi

# Cuckoo sandbox JSON reports
mkdir -p "$BASE_DIR/sandbox_behavior/cuckoo_reports"
if [ -z "$(ls -A "$BASE_DIR"/sandbox_behavior/cuckoo_reports 2>/dev/null)" ]; then
    if [ -n "$CUCKOO_DATASET_REF" ]; then
        echo "Downloading Cuckoo report dataset from Kaggle..."
        run_download "Downloading Cuckoo report dataset from Kaggle..." \
            "$KAGGLE_BIN" datasets download -d "$CUCKOO_DATASET_REF" -p "$BASE_DIR/sandbox_behavior/cuckoo_reports/" --unzip
    elif [ -n "$CUCKOO_REPORTS_URL" ]; then
        echo "Downloading Cuckoo reports archive..."
        archive_path="$BASE_DIR/sandbox_behavior/cuckoo_reports/cuckoo_reports_archive"
        if ! curl -L "$CUCKOO_REPORTS_URL" -o "$archive_path"; then
            echo "WARNING: Failed to download Cuckoo archive from URL."
            FAILED_DOWNLOADS=$((FAILED_DOWNLOADS + 1))
        fi
        case "$CUCKOO_REPORTS_URL" in
            *.zip) unzip -o "$archive_path" -d "$BASE_DIR/sandbox_behavior/cuckoo_reports/" ;;
            *.tar.gz|*.tgz) tar -xzf "$archive_path" -C "$BASE_DIR/sandbox_behavior/cuckoo_reports/" ;;
            *.tar) tar -xf "$archive_path" -C "$BASE_DIR/sandbox_behavior/cuckoo_reports/" ;;
            *) echo "Downloaded Cuckoo archive, but unknown format. Extract manually from $archive_path" ;;
        esac
    else
        echo "Skipping Cuckoo reports dataset. Set CUCKOO_DATASET_REF=<owner/dataset> or CUCKOO_REPORTS_URL=<archive_url>."
    fi
else
    echo "Cuckoo report data already exists. Skipping."
fi

echo "Kaggle Dataset downloads complete!"
if [ "$FAILED_DOWNLOADS" -gt 0 ]; then
    echo "Completed with warnings: $FAILED_DOWNLOADS dataset download(s) failed."
else
    echo "All configured dataset downloads succeeded."
fi
