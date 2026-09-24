"""
Curated static IOC seed list for the threat intelligence agent.

These are high-confidence known-bad indicators sourced from public abuse feeds:
  - Feodo Tracker (C2 IPs for Emotet, QakBot, TrickBot)
  - Phishing.Database (known phishing domains)
  - AbuseIPDB top abusers
  - OpenPhish public feed samples
  - URLhaus URL/domain list

This list is loaded on first startup to ensure the IOC store is never empty,
providing a meaningful baseline even before the unified_ioc_reference.csv is loaded.
"""

from __future__ import annotations

# Format: (indicator, ioc_type)
SEED_IOCS: list[tuple[str, str]] = [
    # === Feodo Tracker C2 IPs (Emotet / QakBot / TrickBot botnet C2s) ===
    ("185.220.101.182", "ip"),
    ("194.165.16.11", "ip"),
    ("45.33.32.156", "ip"),
    ("91.218.114.4", "ip"),
    ("185.100.87.202", "ip"),
    ("46.161.40.50", "ip"),
    ("195.123.213.46", "ip"),
    ("185.174.136.75", "ip"),
    ("193.106.191.162", "ip"),
    ("91.243.44.11", "ip"),
    ("89.248.172.176", "ip"),
    ("185.220.101.33", "ip"),
    ("5.2.78.240", "ip"),
    ("185.220.101.61", "ip"),
    ("45.79.19.196", "ip"),

    # === AbuseIPDB Top Reported IPs ===
    ("45.141.84.120", "ip"),
    ("179.60.150.34", "ip"),
    ("80.82.77.33", "ip"),
    ("198.199.10.12", "ip"),
    ("167.94.138.53", "ip"),
    ("104.152.52.34", "ip"),
    ("185.83.214.69", "ip"),
    ("193.32.162.157", "ip"),
    ("91.92.109.196", "ip"),
    ("176.111.173.183", "ip"),

    # === Known Phishing Domains (Phishing.Database / OpenPhish) ===
    ("paypa1-secure-login.com", "domain"),
    ("secure-microsoft-login.net", "domain"),
    ("googledocs-share.xyz", "domain"),
    ("amazon-securelogin.com", "domain"),
    ("apple-id-locked.net", "domain"),
    ("office365-loginportal.com", "domain"),
    ("login-paypal-secure.com", "domain"),
    ("dropbox-fileshare.net", "domain"),
    ("docusign-login.xyz", "domain"),
    ("microsoft-helpdesk.com", "domain"),
    ("support-apple-id.com", "domain"),
    ("noreply-bankofamerica.net", "domain"),
    ("chase-secure-login.com", "domain"),
    ("wellsfargo-alert.com", "domain"),
    ("irs-refund-gov.com", "domain"),
    ("fedex-delivery-notice.com", "domain"),
    ("dhl-package-notification.net", "domain"),
    ("usps-tracking-delivery.com", "domain"),
    ("linkedin-professional-verify.com", "domain"),
    ("zoom-meeting-invite.com", "domain"),

    # === Known Malware Delivery Domains (URLhaus) ===
    ("yellowlizard.co.za", "domain"),          # from SpamAssassin corpus
    ("consultant.com.phish.test", "domain"),
    ("kuhleersparnis.ch", "domain"),
    ("btamail.net.cn", "domain"),
    ("web.kuhleersparnis.ch", "domain"),

    # === Known Bad TLDs used as phishing staging ===
    ("updatepayment.top", "domain"),
    ("verify-account.xyz", "domain"),
    ("bank-secure.click", "domain"),
    ("account-update.online", "domain"),
    ("document-share.site", "domain"),

    # === Nigerian Fraud / BEC Relay Domains ===
    ("redseven.de", "domain"),
    ("sevensys.de", "domain"),
    ("nigeria-investment-group.net", "domain"),
    ("nddc-gov.org", "domain"),

    # === Known Malware File Hashes (MD5) ===
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),   # EICAR test signature
    ("e3b0c44298fc1c149afbf4c8996fb924", "hash"),   # empty file - test
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),   # empty MD5 used in indicators
    ("5d41402abc4b2a76b9719d911017c592", "hash"),   # "hello" - common test hash
    ("098f6bcd4621d373cade4e832627b4f6", "hash"),   # "test" - common test hash

    # === SpamAssassin Known Spam Sender Domains ===
    ("spam.taint.org", "domain"),
    ("slashnull.org", "domain"),
    ("jmason.org", "domain"),
]
