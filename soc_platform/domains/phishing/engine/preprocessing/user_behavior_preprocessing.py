"""
Advanced Data Generation and Preprocessing for the User Behavior ML Agent.
Synthesizes a full virtual enterprise network (roster, social graph, inbound mail)
and outputs a compiled feature dataset ready for XGBoost.
"""

from soc_platform.domains.phishing.engine.paths import PHISHING_HOME
import os
import sqlite3
import random
import time
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

from soc_platform.domains.phishing.engine.preprocessing.user_behavior_feature_contract import extract_behavior_features

# ---------------------------------------------------------------------------
# Virtual Enterprise Constants
# ---------------------------------------------------------------------------
COMPANY_DOMAIN = "acmecorp.net"
DEPARTMENTS = ["finance", "hr", "executive", "sales", "marketing", "operations", "engineering", "it"]

COMMON_EXT_DOMAINS = ["gmail.com", "outlook.com", "microsoft.com", "salesforce.com", "aws.amazon.com", "atlassian.com"]
PHISHING_DOMAINS = ["login-acmecorp.net", "secure-auth-update.com", "hr-benefits-portal.xyz", "microsoft-support.info"]

WORKSPACE_ROOT = PHISHING_HOME
# ---------------------------------------------------------------------------
# Generator Functions
# ---------------------------------------------------------------------------
def _init_sqlite_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.executescript(
        """
        DROP TABLE IF EXISTS employees;
        CREATE TABLE employees (
            email_address TEXT PRIMARY KEY,
            department TEXT NOT NULL
        );
        
        DROP TABLE IF EXISTS interactions;
        CREATE TABLE interactions (
            recipient_email TEXT NOT NULL,
            sender_domain TEXT NOT NULL,
            interaction_count INTEGER DEFAULT 0,
            days_since_last REAL DEFAULT 365.0,
            PRIMARY KEY (recipient_email, sender_domain)
        );
        """
    )
    conn.commit()
    return conn

def build_virtual_enterprise(db_path: Path):
    """Generates the company roster and the benign behavioral baseline."""
    print("[1/3] Synthesizing Corporate Roster & Social Graph...")
    conn = _init_sqlite_db(db_path)
    c = conn.cursor()
    
    # 1. Roster
    employees = []
    for i in range(5000):
        dept = random.choice(DEPARTMENTS)
        email = f"emp_{i}@{COMPANY_DOMAIN}"
        employees.append((email, dept))
        
    c.executemany("INSERT INTO employees VALUES (?, ?)", employees)
    
    # 2. Interactions (Baseline graph)
    # Most users talk internally, and to a few external domains.
    interactions = []
    for emp_email, emp_dept in employees:
        # Internal contacts
        interactions.append((emp_email, COMPANY_DOMAIN, random.randint(10, 500), random.uniform(0.1, 5.0)))
        
        # Familiar external contacts
        for ext in random.sample(COMMON_EXT_DOMAINS, k=random.randint(2, 5)):
            interactions.append((emp_email, ext, random.randint(2, 50), random.uniform(1.0, 30.0)))
            
    c.executemany("INSERT INTO interactions VALUES (?, ?, ?, ?)", interactions)
    conn.commit()
    return conn, employees

def synthesize_email_payloads(conn: sqlite3.Connection, employees: list) -> pd.DataFrame:
    """Generates 50,000 distinct email payloads covering Benign and Malicious edge cases."""
    print("[2/3] Simulating Inbound Email Traffic...")
    
    records = []
    c = conn.cursor()
    
    for i in range(50000):
        # 80% Benign, 20% Anomalous
        is_anomalous = random.random() < 0.20
        recipient, dept = random.choice(employees)
        
        if not is_anomalous:
            # Benign
            sender_domain = random.choice([COMPANY_DOMAIN] + COMMON_EXT_DOMAINS)
            sender = f"user_{random.randint(1,100)}@{sender_domain}"
            subject = "Project Update" if random.random() > 0.1 else "Important Action Required" 
            urls = [] if random.random() > 0.5 else ["http://internal.wiki/doc"]
            label = 0
            
        else:
            # Malicious / Behaviorally Anomalous
            # E.g., spoofed internal name from bizarre domain, highly urgent
            scenario = random.choice(["spear_phish", "cold_exec_spoof", "payroll_fraud"])
            
            if scenario == "spear_phish":
                sender = f"admin@{random.choice(PHISHING_DOMAINS)}"
                subject = "URGENT: Password Reset Required Immediately"
                urls = ["http://evil.com/login"]
            elif scenario == "cold_exec_spoof":
                sender = f"ceo_personal@gmail.com"
                subject = "Urgent wire transfer needed"
                urls = []
            else:
                sender = f"hr-dept@{random.choice(PHISHING_DOMAINS)}"
                subject = "Final Notice: Action Required for Benefits Enrollment"
                urls = ["http://benefits.xyz"]
                
            # If the user is in an inherently high-risk/high-target tier, label 1 is highly confident
            # "Is clicked" proxy
            label = 1
            
        payload = {
            "headers": {"sender": sender, "subject": subject},
            "to": [recipient],
            "urls": urls
        }
        
        # Apply the feature extraction pipeline dict -> vector natively
        features_dict = extract_behavior_features(payload, c)
        vec = features_dict["numeric_vector"][0]
        
        # vec order: contact_count, days_since_last, is_internal, is_business, urgency, link, dept_risk
        records.append({
            "contact_count": vec[0],
            "days_since_last_contact": vec[1],
            "is_internal_domain": vec[2],
            "is_business_hours": vec[3],
            "urgency_score": vec[4],
            "link_count": vec[5],
            "dept_risk_tier": vec[6],
            "label": label
        })
        
    return pd.DataFrame(records)

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(output_dir: str = "datasets_processed") -> str:
    output_path = WORKSPACE_ROOT / output_dir / "user_behavior"
    output_path.mkdir(parents=True, exist_ok=True)
    
    target_csv = output_path / "user_behavior_training.csv"
    db_path = WORKSPACE_ROOT / "data" / "behavior_graph.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn, employees = build_virtual_enterprise(db_path)
    df = synthesize_email_payloads(conn, employees)
    
    print("[3/3] Saving Compiled Metrics to CSV...")
    df.to_csv(target_csv, index=False)
    conn.close()
    
    return str(target_csv)

if __name__ == "__main__":
    out = run()
    print(f"Pipeline complete. Saved to {out}")
