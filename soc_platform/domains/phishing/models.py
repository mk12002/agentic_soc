"""Phishing workflow state: one row per user-reported (or gateway-reported) message (PH-F01, PH-F13)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import new_id, utcnow


class Submission(Base):
    __tablename__ = "ph_submissions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    source: Mapped[str] = mapped_column(String(64))            # defender_office365 | avanan | upload | shared_mailbox
    source_ref: Mapped[str] = mapped_column(String(512), unique=True)  # report message id / event id (dedupe on replay)
    reporter: Mapped[str | None] = mapped_column(BoundedText(256), nullable=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    internet_message_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(BoundedText(1024), default="")
    sender: Mapped[str | None] = mapped_column(BoundedText(512), nullable=True)
    mime_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)  # new|analysed|auto_closed|escalated|closed
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    campaign_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    auto_closed: Mapped[bool] = mapped_column(Boolean, default=False)
    sampled_for_review: Mapped[bool] = mapped_column(Boolean, default=False)
    feedback_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
