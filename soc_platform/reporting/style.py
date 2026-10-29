"""The organisation's report style: what every generated Word report and PowerPoint deck looks like and how its
narrative is worded.

A lead or an administrator sets it on the *Reports* screen, without a code change:

* **brand** - organisation name (running header and footer), primary and accent colours, font, classification line,
  footer text
* **logo** (PNG / JPEG) - on the cover band, every page's header and the title slide; re-encoded as PNG on upload
* **Word template** (.docx / .dotx) - the base document: its styles, page set-up, header and footer are kept (the
  house header / footer are added only where the template has none); its sample body text is removed
* **PowerPoint template** (.pptx / .potx, 16:9) - the slide master and layouts; its sample slides are removed
* **writing guide** (a skill: .md / .txt) - tone, terms and wording for the model-written narrative. It shapes words
  only: facts and figures still come from the platform's records, every sentence must still cite them, and the
  deterministic text (no model, or over a limit) is unchanged
* a **style pack** (.zip) with any of these, plus ``brand.json`` / ``brand.yaml`` for the brand settings

Every change is a new version (who, when, why; audited); the newest is in force; *Reset* returns to the house style.
Uploaded files are validated (macros refused, DTDs refused, size caps against zip bombs), kept encrypted in the
database (``blobs``, whatever ``SOC_BLOB_STORE`` is, so every replica renders with them) and applied through a
context (``use_style``) so concurrent reports never mix styles.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import re
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow

DEFAULT: dict[str, Any] = {"organisation": "", "primary": "1F2A44", "accent": "2563EB", "font": "Calibri",
                           "classification": "Confidential - internal", "footer": "", "guide": "", "files": {}}
SLOTS = {"word": "Word template", "deck": "PowerPoint template", "logo": "Logo", "guide": "Writing guide"}
MAX_FILE = 15_000_000             # an uploaded file (a template with fonts and images embedded can be large)
MAX_UNPACKED = 60_000_000         # all parts of one Office file or style pack, unpacked
MAX_LOGO = 3_000_000
MAX_GUIDE = 8_000                 # characters: the guide goes into every narrative prompt, so it is kept short
_HEX = re.compile(r"#?[0-9A-Fa-f]{6}")
_FONT = re.compile(r"[A-Za-z0-9 \-]{1,40}")
_CT_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
_CT_DOTX = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
_CT_PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
_CT_POTX = "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml"


class ReportStyleVersion(Base):
    """One version of the report style; the newest row is in force."""

    __tablename__ = "report_styles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    set_by: Mapped[str] = mapped_column(String(256))
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class StyleRejected(ValueError):
    """An upload or a setting that cannot be used; the message says why and what to do."""


# ---------------------------------------------------------------------------------------------- checking


def check_brand(values: dict[str, Any]) -> dict[str, str]:
    """The brand settings in their stored form, or StyleRejected naming every problem."""
    out: dict[str, str] = {}
    problems: list[str] = []
    for k, v in values.items():
        if k not in ("organisation", "primary", "accent", "font", "classification", "footer", "guide"):
            problems.append(f"unknown setting '{k}' (organisation, primary, accent, font, classification, footer, guide)")
            continue
        s = "" if v is None else str(v).strip()
        if any(ord(c) < 32 and c not in "\n\t" for c in s):
            problems.append(f"{k}: contains control characters")
        elif k in ("primary", "accent"):
            if not _HEX.fullmatch(s):
                problems.append(f"{k}: a colour as six hex digits, e.g. 1F2A44")
            else:
                out[k] = s.lstrip("#").upper()
        elif k == "font":
            if not _FONT.fullmatch(s):
                problems.append("font: a font name of letters, digits, spaces and hyphens (e.g. Arial, Segoe UI)")
            else:
                out[k] = s
        elif k == "guide":
            if len(s) > MAX_GUIDE:
                problems.append(f"guide: at most {MAX_GUIDE:,} characters (this one has {len(s):,}) - keep the essentials")
            else:
                out[k] = s
        else:
            limit = {"organisation": 80, "classification": 80, "footer": 160}[k]
            if "\n" in s or len(s) > limit:
                problems.append(f"{k}: one line of at most {limit} characters")
            elif k == "classification" and not s:
                problems.append("classification: cannot be empty (e.g. Confidential - internal)")
            else:
                out[k] = s
    if problems:
        raise StyleRejected("; ".join(problems))
    return out


def _zip(data: bytes, what: str) -> zipfile.ZipFile:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise StyleRejected(f"{what}: not a readable file of that kind") from exc
    if sum(i.file_size for i in z.infolist()) > MAX_UNPACKED or len(z.infolist()) > 5_000:
        raise StyleRejected(f"{what}: too large once unpacked")
    return z


def _office(data: bytes, what: str, template_ct: str, document_ct: str) -> bytes:
    """An Office file's bytes as a document (a template's content type rewritten), refused if it carries macros or
    declares a DTD / entity in any XML part."""
    z = _zip(data, what)
    names = set(z.namelist())
    if "[Content_Types].xml" not in names:
        raise StyleRejected(f"{what}: not an Office Open XML file")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise StyleRejected(f"{what}: contains macros - save it as a macro-free file (.docx / .dotx, .pptx / .potx)")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as w:
        for info in z.infolist():
            body = z.read(info)
            if info.filename.endswith((".xml", ".rels")) and (b"<!DOCTYPE" in body or b"<!ENTITY" in body):
                raise StyleRejected(f"{what}: a part declares a document type - not a normal Office file")
            if info.filename == "[Content_Types].xml":
                body = body.replace(template_ct.encode(), document_ct.encode())
            w.writestr(info, body)
    return out.getvalue()


def check_word(data: bytes) -> tuple[bytes, str]:
    from docx import Document

    doc_bytes = _office(data, "Word template", _CT_DOTX, _CT_DOCX)
    try:
        d = Document(io.BytesIO(doc_bytes))
    except Exception as exc:
        raise StyleRejected(f"Word template: cannot be opened ({type(exc).__name__})") from exc
    sec = d.sections[0]
    return doc_bytes, (f"{len(d.styles)} styles; page {sec.page_width.cm:.1f} x {sec.page_height.cm:.1f} cm"
                       if sec.page_width and sec.page_height else f"{len(d.styles)} styles")


def check_deck(data: bytes) -> tuple[bytes, str]:
    from pptx import Presentation

    deck_bytes = _office(data, "PowerPoint template", _CT_POTX, _CT_PPTX)
    try:
        prs = Presentation(io.BytesIO(deck_bytes))
    except Exception as exc:
        raise StyleRejected(f"PowerPoint template: cannot be opened ({type(exc).__name__})") from exc
    w, h = int(prs.slide_width or 0), int(prs.slide_height or 0)
    if not h or abs(w / h - 16 / 9) > 0.02:
        raise StyleRejected(f"PowerPoint template: the decks are laid out for 16:9 slides; this one is "
                            f"{w / 914400:.2f} x {h / 914400:.2f} in - set Design > Slide Size > Widescreen")
    return deck_bytes, f"16:9; {len(prs.slide_layouts)} layouts"


def check_logo(data: bytes) -> tuple[bytes, str]:
    from PIL import Image, UnidentifiedImageError

    if len(data) > MAX_LOGO:
        raise StyleRejected(f"Logo: at most {MAX_LOGO // 1_000_000} MB")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        img = Image.open(io.BytesIO(data))
        if img.format not in ("PNG", "JPEG") or img.width > 5000 or img.height > 5000:
            raise StyleRejected("Logo: a PNG or JPEG image, at most 5000 pixels a side")
        out = io.BytesIO()
        img.convert("RGBA").save(out, "PNG")       # re-encoded: no metadata, nothing but the picture
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise StyleRejected("Logo: not a readable PNG or JPEG image") from exc
    return out.getvalue(), f"{img.width} x {img.height} px"


def check_guide(data: bytes) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise StyleRejected("Writing guide: a UTF-8 text or Markdown file") from exc
    return check_brand({"guide": text.replace("\r\n", "\n")})["guide"]


def _kind(name: str) -> str | None:
    n = name.lower()
    for ext, slot in ((".docx", "word"), (".dotx", "word"), (".pptx", "deck"), (".potx", "deck"), (".png", "logo"),
                      (".jpg", "logo"), (".jpeg", "logo"), (".md", "guide"), (".markdown", "guide"), (".txt", "guide"),
                      (".zip", "pack"), (".json", "brand"), (".yaml", "brand"), (".yml", "brand")):
        if n.endswith(ext):
            return slot
    if n.endswith((".docm", ".dotm", ".pptm", ".potm")):
        raise StyleRejected(f"{name}: a macro-enabled file - save it without macros (.docx / .dotx, .pptx / .potx)")
    return None


def _brand_file(data: bytes, name: str) -> dict[str, str]:
    try:
        if name.lower().endswith(".json"):
            values = json.loads(data.decode("utf-8-sig"))
        else:
            import yaml

            values = yaml.safe_load(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise StyleRejected(f"{name}: not valid JSON / YAML") from exc
    except Exception as exc:
        raise StyleRejected(f"{name}: not valid YAML ({type(exc).__name__})") from exc
    if not isinstance(values, dict):
        raise StyleRejected(f"{name}: expected settings such as primary, accent, font, organisation, classification")
    return check_brand(values)


# ---------------------------------------------------------------------------------------------- the store


class ReportStyleStore:
    def __init__(self, session: Session) -> None:
        self.s = session

    def _blobs(self) -> Any:
        from soc_platform.config import get_settings
        from soc_platform.core.blobstore import BlobStore

        # always in the database: every replica renders with the same files, encrypted like every stored blob
        return BlobStore(self.s, get_settings().model_copy(update={"blob_store": "database"}))

    def active_row(self) -> ReportStyleVersion | None:
        return self.s.execute(select(ReportStyleVersion).order_by(ReportStyleVersion.id.desc()).limit(1)).scalars().first()

    def active(self) -> dict[str, Any]:
        row = self.active_row()
        return {**copy.deepcopy(DEFAULT), **copy.deepcopy((row.document if row else None) or {})}

    def view(self) -> dict[str, Any]:
        row = self.active_row()
        doc = self.active()
        return {"style": doc, "version": row.id if row else None, "defaults": DEFAULT, "slots": SLOTS,
                "custom": doc != DEFAULT,
                "history": [{"id": r.id, "set_by": r.set_by, "note": r.note, "created_at": r.created_at.isoformat()}
                            for r in self.s.execute(select(ReportStyleVersion).order_by(ReportStyleVersion.id.desc())
                                                    .limit(30)).scalars()]}

    def assets(self) -> dict[str, Any]:
        """The style in force with its files' bytes (what rendering needs). A file that cannot be read is left out
        (the house style is used for that part) rather than failing a report."""
        doc = self.active()
        store = self._blobs()
        for slot, meta in list((doc.get("files") or {}).items()):
            try:
                doc[f"{slot}_bytes"] = store.get(meta["ref"])
            except Exception as exc:  # noqa: BLE001 - a missing style file must not stop a report; logged
                from soc_platform.core.observability import event

                event("report_style.file_unreadable", 30, slot=slot, error=type(exc).__name__)
        return doc

    # ------------------------------------------------------------- changing
    def _save(self, doc: dict[str, Any], by: Principal, note: str, changes: dict[str, Any]) -> ReportStyleVersion:
        if by.is_service or by.is_agent or not by.can(Perm.MANAGE_REPORT_STYLE):
            raise PermissionError("a lead or an administrator (manage_report_style) changes the report style")
        if not changes:
            raise StyleRejected("this changes nothing in the report style in force")
        row = ReportStyleVersion(document=doc, set_by=by.id, note=(note or "")[:2000])
        self.s.add(row)
        self.s.flush()
        AuditLog(self.s).append(actor_type=by.actor_type, actor_id=by.id, event_type="report_style.changed",
                                subject_type="report_style", subject_id=str(row.id),
                                payload={"note": (note or "")[:500], "changes": changes})
        return row

    def set_brand(self, values: dict[str, Any], by: Principal, note: str = "") -> ReportStyleVersion:
        clean = check_brand({k: v for k, v in values.items() if v is not None})
        doc = self.active()
        changes = {k: {"from": doc.get(k) if k != "guide" else f"{len(doc.get(k) or '')} characters",
                       "to": v if k != "guide" else f"{len(v)} characters"}
                   for k, v in clean.items() if doc.get(k) != v}
        doc.update(clean)
        return self._save(doc, by, note, changes)

    def upload(self, filename: str, data: bytes, by: Principal, note: str = "") -> dict[str, Any]:
        """Apply one uploaded file - a template, a logo, a writing guide, brand settings or a .zip style pack."""
        if not by.can(Perm.MANAGE_REPORT_STYLE) or by.is_service or by.is_agent:
            raise PermissionError("a lead or an administrator (manage_report_style) changes the report style")
        if len(data) > MAX_FILE:
            raise StyleRejected(f"the file is larger than {MAX_FILE // 1_000_000} MB")
        name = (filename or "upload").replace("\\", "/").rsplit("/", 1)[-1][:120]
        kind = _kind(name)
        if kind is None:
            raise StyleRejected(f"{name}: not a style file - upload .docx / .dotx, .pptx / .potx, .png / .jpg, "
                                ".md / .txt (writing guide), brand.json / .yaml, or a .zip with any of these")
        items = self._pack(data) if kind == "pack" else [(name, kind, data)]
        doc = self.active()
        changes: dict[str, Any] = {}
        applied = []
        for fname, k, body in items:
            if k == "brand":
                vals = _brand_file(body, fname)
                for key, v in vals.items():
                    if doc.get(key) != v:
                        changes[key] = {"from": doc.get(key) if key != "guide" else "...", "to": v if key != "guide" else "..."}
                        doc[key] = v
                applied.append({"slot": "brand", "file": fname, "detail": ", ".join(sorted(vals)) or "nothing"})
                continue
            if k == "guide":
                text = check_guide(body)
                changes["guide"] = {"file": fname, "characters": len(text)}
                doc["guide"] = text
                applied.append({"slot": "guide", "file": fname, "detail": f"{len(text):,} characters"})
                continue
            stored, detail = {"word": check_word, "deck": check_deck, "logo": check_logo}[k](body)
            digest = hashlib.sha256(stored).hexdigest()
            ext = {"word": "docx", "deck": "pptx", "logo": "png"}[k]
            ref = self._blobs().put(f"report_style/{digest}.{ext}", f"report_style/{digest}.{ext}", stored)
            doc.setdefault("files", {})[k] = {"ref": ref, "name": fname, "size": len(stored), "sha256": digest,
                                              "detail": detail, "by": by.id, "at": utcnow().isoformat()}
            changes[k] = {"file": fname, "sha256": digest[:16], "detail": detail}
            applied.append({"slot": k, "file": fname, "detail": detail})
        row = self._save(doc, by, note or f"uploaded {name}", changes)
        return {"version": row.id, "applied": applied}

    @staticmethod
    def _pack(data: bytes) -> list[tuple[str, str, bytes]]:
        z = _zip(data, "Style pack")
        found: dict[str, tuple[str, bytes]] = {}
        for info in z.infolist():
            base = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
            if info.is_dir() or not base or base.startswith((".", "~$")) or "__MACOSX" in info.filename:
                continue
            k = _kind(base)
            if k is None or k == "pack":
                continue
            if k in found:
                raise StyleRejected(f"Style pack: two files for the {('brand settings' if k == 'brand' else SLOTS[k]).lower()} "
                                    f"({found[k][0]}, {base}) - keep one")
            found[k] = (base, z.read(info))
        if not found:
            raise StyleRejected("Style pack: no style file inside (.docx / .dotx, .pptx / .potx, .png / .jpg, .md, "
                                "brand.json / .yaml)")
        order = ("brand", "guide", "logo", "word", "deck")
        return [(found[k][0], k, found[k][1]) for k in order if k in found]

    def remove(self, slot: str, by: Principal, note: str = "") -> ReportStyleVersion:
        if slot not in SLOTS:
            raise StyleRejected(f"unknown part '{slot}' ({', '.join(SLOTS)})")
        doc = self.active()
        if slot == "guide":
            changed = bool(doc.get("guide"))
            doc["guide"] = ""
        else:
            changed = slot in (doc.get("files") or {})
            doc.get("files", {}).pop(slot, None)
        return self._save(doc, by, note or f"removed the {SLOTS[slot].lower()}", {slot: "removed"} if changed else {})

    def reset(self, by: Principal, note: str = "") -> ReportStyleVersion:
        changed = self.active() != DEFAULT
        return self._save(copy.deepcopy(DEFAULT), by, note or "back to the house style",
                          {"reset": "house style"} if changed else {})


# ---------------------------------------------------------------------------------------------- applying it


@contextmanager
def use_style(session: Session) -> Iterator[dict[str, Any]]:
    """Render everything inside with the style in force (Word and PowerPoint layout, logo, templates, guide)."""
    from soc_platform.reporting import design as D

    style = ReportStyleStore(session).assets()
    token = D.STYLE.set(style)
    try:
        yield style
    finally:
        D.STYLE.reset(token)


def guide_instruction(guide: str | None) -> str:
    """The writing guide as a prompt instruction - wording only, never facts, figures or citations."""
    g = (guide or "").strip()
    return ("" if not g else
            "\n\nHOUSE WRITING STYLE (the organisation's guide - follow it for tone, terms and wording only; it never "
            "changes a fact, a figure, what may be claimed or the citation rules above):\n" + g)


def preview(session: Session, fmt: str) -> bytes:
    """A short sample report in the style in force (made-up example figures, labelled as such), to check the look
    before it reaches a real report. Nothing is stored."""
    from pptx.util import Inches

    from soc_platform.reporting import design as D

    tiles = [("Open findings", 42, "neutral"), ("Past SLA", 3, "bad"), ("Closed this week", 17, "good")]
    rows = [["Phishing campaign contained", "high", "Closed"], ["Exposed server patched", "critical", "Closed"],
            ["Unusual sign-in reviewed", "medium", "Open"]]
    buf = io.BytesIO()
    with use_style(session):
        if fmt == "pptx":
            prs = D.new_deck()
            D.title_slide(prs, "Report style preview", "Sample figures - not from your data",
                          f"{D.brand()}  ·  {D.classification()}")
            s = D.content_slide(prs, "A content slide", "Report style preview", 2, "Tiles, a table and a chart")
            D.deck_tiles(s, tiles, Inches(0.6), Inches(1.8), Inches(5.6))
            D.deck_table(s, ["Item", "Severity", "Status"], rows, Inches(6.6), Inches(1.8), Inches(6.1), tone_col=1)
            D.deck_chart(s, {"title": "Findings by team", "categories": ["Network", "Identity", "Endpoint"],
                             "series": [{"name": "Findings", "values": [5, 3, 8]}]},
                         Inches(0.6), Inches(4.4), Inches(5.6), Inches(2.5))
            prs.save(buf)
        else:
            d = D.new_document("Report style preview")
            D.cover(d, "Report style preview", "Sample figures - not from your data",
                    f"{D.brand()}  ·  {D.classification()}")
            D.tiles(d, tiles)
            D.section(d, "A section", "Headings, body text, tables and status colours as every report shows them.")
            D.paragraph(d, "Narrative is written here, citing the computed figures it is based on [F1].")
            D.table(d, ["Item", "Severity", "Status"], rows, tone_col=1)
            D.note(d, D.footer_text())
            d.save(buf)
    return buf.getvalue()
