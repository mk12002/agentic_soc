"""Saved report specifications (reports described in words and kept for reuse)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import new_id, utcnow


class ReportTemplate(Base):
    __tablename__ = "report_templates"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(BoundedText(160))
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ValueInput(Base):
    """A figure the platform cannot measure itself, entered by a SOC lead for the value scorecard (``reporting/value``):
    a baseline measured before the pilot, a target, or a time-study measurement during it. Keyed by (kpi, kind); a
    new value replaces the old one and every change is audited."""

    __tablename__ = "value_inputs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    kpi: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(16))                 # baseline | target | measured
    value: Mapped[float] = mapped_column(Float)
    note: Mapped[str] = mapped_column(BoundedText(500), default="")   # source: "ServiceNow Jan-Mar", "time study wk 1-2"
    set_by: Mapped[str] = mapped_column(String(256))
    set_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
