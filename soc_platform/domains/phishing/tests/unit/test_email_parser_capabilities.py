"""Tests around supported extension handling in EmailParserService."""

from __future__ import annotations

import pytest

from soc_platform.domains.phishing.engine.configs.settings import settings
from soc_platform.domains.phishing.engine.services.email_parser import EmailParserService


@pytest.fixture()
def parser(tmp_path):
    settings.attachment_volume_dir = str(tmp_path / "attachments")
    return EmailParserService()


def test_supported_extensions_include_eml_and_txt(parser: EmailParserService) -> None:
    exts = parser.supported_extensions()
    assert ".eml" in exts
    assert ".txt" in exts


def test_msg_support_matches_runtime_capability(parser: EmailParserService) -> None:
    msg_supported = parser.supports_extension(".msg")
    listed = ".msg" in parser.supported_extensions()
    assert msg_supported == listed
