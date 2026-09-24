import os
from pathlib import Path

def create_dummy_data():
    base_dir = Path("datasets")
    
    # 1. Emails
    email_dir = base_dir / "email_content"
    email_dir.mkdir(parents=True, exist_ok=True)
    with open(email_dir / "sample1.eml", "w") as f:
        f.write("From: attacker@example.com\nTo: victim@example.com\nSubject: Urgent Invoice\n\nPlease pay attached invoice.")
    with open(email_dir / "sample2.txt", "w") as f:
        f.write("This is a raw text email without headers.")

    # 2. URLs
    url_dir = base_dir / "url_dataset"
    url_dir.mkdir(parents=True, exist_ok=True)
    with open(url_dir / "phish_urls.csv", "w") as f:
        f.write("url,label\nhttp://malicious.com/login,1\nhttp://benign.com/home,0\n")
    with open(url_dir / "openphish.csv", "w") as f:
        f.write("url\nhttp://phishing2.com/secure\nhttp://phishing3.com/update\n")

    # 3. Attachments
    att_dir = base_dir / "attachments"
    att_dir.mkdir(parents=True, exist_ok=True)
    with open(att_dir / "malware1.exe", "wb") as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00")
    with open(att_dir / "document.pdf", "w") as f:
        f.write("%PDF-1.4\n%EOF")

    # 4. Threat Intel IOCs
    ioc_dir = base_dir / "threat_intelligence"
    ioc_dir.mkdir(parents=True, exist_ok=True)
    with open(ioc_dir / "abuseipdb.csv", "w") as f:
        f.write("indicator,type,source\n192.168.1.100,ip,abuseipdb\nmalicious-domain.com,domain,abuseipdb\n")
    with open(ioc_dir / "urlhaus.json", "w") as f:
        f.write('{"indicator": "http://bad-url.com", "type": "url", "source": "urlhaus"}\n')
        f.write('{"indicator": "http://worse-url.com", "type": "url", "source": "urlhaus"}\n')

if __name__ == "__main__":
    create_dummy_data()
    print("Dummy dataset created successfully.")
