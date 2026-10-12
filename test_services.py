from __future__ import annotations

from pathlib import Path

import fitz
import pytest

from backend.app.services.feeds import is_trusted_feed_url
from backend.app.services.ioc import build_ioc_rows, normalize_ioc
from backend.app.services.pdf_analyzer import analyze_pdf, validate_pdf
from backend.app.services.risk import score_analysis


def sample_pdf() -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Review https://example.test/path and 192.0.2.10")
    data = doc.tobytes()
    doc.close()
    return data


def test_pdf_magic_and_size_validation():
    assert validate_pdf(sample_pdf(), "sample.pdf", 1024 * 1024)[0]
    assert not validate_pdf(b"not a pdf", "sample.pdf", 1024)[0]
    assert not validate_pdf(sample_pdf(), "sample.txt", 1024 * 1024)[0]


def test_analysis_extracts_sha_metadata_urls_and_ip():
    result = analyze_pdf(sample_pdf(), "sample.pdf")
    assert len(result["sha256"]) == 64
    assert result["page_count"] == 1
    assert any(item["type"] == "url" for item in result["iocs"])
    assert any(item["type"] == "ip" for item in result["iocs"])
    assert result["parsing_status"] in {"readable", "partially_inspected"}


def test_marker_detection_and_risk_scoring():
    content = sample_pdf() + b" /JavaScript /JS /OpenAction /EmbeddedFile"
    result = analyze_pdf(content, "signals.pdf")
    assert any(item["code"] == "javascript" and item["status"] == "detected" for item in result["findings"])
    scored = score_analysis(result)
    assert scored["risk_score"] >= 35
    assert scored["risk_class"] in {"Medium", "High", "Critical"}


def test_ioc_normalization_and_deduplication():
    rows = build_ioc_rows([
        {"type": "domain", "value": "Example.COM."},
        {"type": "domain", "value": "example.com"},
        {"type": "url", "value": "HTTPS://Example.com/a/"},
    ])
    assert len(rows) == 2
    assert normalize_ioc("Example.COM.", "domain") == "example.com"
    assert normalize_ioc("HTTPS://Example.com/a/", "url") == "https://example.com/a/"


def test_feed_allowlist_rejects_arbitrary_urls():
    assert is_trusted_feed_url("https://urlhaus.abuse.ch/downloads/csv_recent/")
    assert not is_trusted_feed_url("https://example.com/feed.csv")
    assert not is_trusted_feed_url("http://urlhaus.abuse.ch/downloads/csv_recent/")
