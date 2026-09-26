"""
PDF Report Generator for the Agentic Email Security System.

Renders a stored threat report (the `decision` dict persisted in the
`threat_reports` table) into a self-contained PDF using reportlab — a
pure-Python engine with no external binary dependencies.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any

from soc_platform.domains.phishing.engine.services.logging_service import get_service_logger

logger = get_service_logger("pdf_report")


def _verdict_color(verdict: str):
    from reportlab.lib import colors

    v = (verdict or "").lower()
    if v in ("malicious", "high_risk"):
        return colors.HexColor("#EF4444")
    if v == "suspicious":
        return colors.HexColor("#F59E0B")
    if v in ("benign", "safe", "low_risk"):
        return colors.HexColor("#10B981")
    return colors.HexColor("#6B7280")


def build_report_pdf(report: dict[str, Any]) -> bytes:
    """Render a threat report dict into PDF bytes.

    Raises ImportError if reportlab is not installed (callers should surface
    this as HTTP 503 rather than crashing).
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    report = report or {}
    analysis_id = str(report.get("analysis_id", "unknown"))
    verdict = str(report.get("verdict", "unknown"))
    risk = float(report.get("overall_risk_score", 0.0) or 0.0)

    styles = getSampleStyleSheet()
    h_style = ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"], spaceBefore=10, spaceAfter=4,
        textColor=colors.HexColor("#1F2937"),
    )
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=12, alignment=TA_LEFT)

    def esc(text: Any) -> str:
        s = "" if text is None else str(text)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, title=f"Threat Report {analysis_id}",
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    flow: list[Any] = []

    # ── Title ──
    flow.append(Paragraph("Email Threat Analysis Report", styles["Title"]))
    flow.append(Paragraph(
        f"Analysis ID: <b>{esc(analysis_id)}</b> &nbsp;|&nbsp; "
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        body,
    ))
    flow.append(Spacer(1, 6))

    # ── Verdict banner ──
    verdict_tbl = Table(
        [[Paragraph(f"<b>VERDICT: {esc(verdict.upper())}</b>", ParagraphStyle(
            "Verdict", parent=body, fontSize=13, textColor=colors.white)),
          Paragraph(f"<b>Risk Score: {risk:.4f}</b>", ParagraphStyle(
              "Risk", parent=body, fontSize=13, textColor=colors.white))]],
        colWidths=[None, 60 * mm],
    )
    verdict_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _verdict_color(verdict)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(verdict_tbl)
    flow.append(Spacer(1, 8))

    # ── LLM explanation ──
    explanation = (report.get("llm_explanation") or "").strip()
    if explanation:
        flow.append(Paragraph("Analyst Summary", h_style))
        flow.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB")))
        flow.append(Paragraph(esc(explanation), body))

    # ── Per-agent risk table ──
    agents = report.get("agent_results") or []
    if isinstance(agents, list) and agents:
        flow.append(Paragraph("Per-Agent Risk", h_style))
        flow.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB")))
        rows = [["Agent", "Risk", "Top Indicators"]]
        for a in agents:
            if not isinstance(a, dict):
                continue
            name = esc(a.get("agent_name", "?"))
            score = a.get("risk_score", a.get("risk", 0.0))
            try:
                score_txt = f"{float(score):.3f}"
            except (TypeError, ValueError):
                score_txt = esc(score)
            indicators = a.get("indicators") or a.get("reasons") or []
            ind_txt = esc("; ".join(str(i) for i in indicators[:4])) if isinstance(indicators, list) else ""
            rows.append([Paragraph(name, body), Paragraph(score_txt, body), Paragraph(ind_txt, body)])
        risk_tbl = Table(rows, colWidths=[40 * mm, 18 * mm, None], repeatRows=1)
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F4F6")]),
        ]))
        flow.append(risk_tbl)

    # ── MITRE ATT&CK techniques ──
    attack = report.get("attack_assessment") or {}
    techniques = attack.get("techniques") if isinstance(attack, dict) else None
    if isinstance(techniques, list) and techniques:
        flow.append(Paragraph("MITRE ATT&CK Techniques", h_style))
        flow.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB")))
        rows = [["Technique", "Tactic", "Confidence"]]
        for t in techniques:
            if not isinstance(t, dict):
                continue
            conf = t.get("confidence", 0.0)
            try:
                conf_txt = f"{float(conf):.2f}"
            except (TypeError, ValueError):
                conf_txt = esc(conf)
            rows.append([
                Paragraph(f"{esc(t.get('technique_id', ''))} {esc(t.get('technique_name', ''))}", body),
                Paragraph(esc(t.get("tactic_name", "")), body),
                Paragraph(conf_txt, body),
            ])
        tech_tbl = Table(rows, colWidths=[None, 45 * mm, 22 * mm], repeatRows=1)
        tech_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        flow.append(tech_tbl)

    # ── Recommended actions ──
    actions = report.get("recommended_actions") or []
    if isinstance(actions, list) and actions:
        flow.append(Paragraph("Recommended Actions", h_style))
        flow.append(HRFlowable(width="100%", color=colors.HexColor("#E5E7EB")))
        for act in actions:
            flow.append(Paragraph(f"• {esc(act)}", body))

    flow.append(Spacer(1, 12))
    flow.append(Paragraph(
        "Generated by the Agentic Email Security System.",
        ParagraphStyle("Footer", parent=body, fontSize=7, textColor=colors.HexColor("#9CA3AF")),
    ))

    doc.build(flow)
    return buf.getvalue()
