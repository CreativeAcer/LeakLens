"""
Tests for scanner/content.py and related engine helpers.
Covers scan_content(), is_placeholder_match(), is_docs_path(), build_finding().
"""
import os
import tempfile
import pytest
from scanner.content import (
    scan_content,
    build_finding,
    is_placeholder,
    is_placeholder_match,
    is_docs_path,
    get_risk_level,
)
from scanner.suppress import load_suppressions, is_suppressed


# ─── get_risk_level ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("conf,expected", [
    (10, "HIGH"),
    (8,  "HIGH"),
    (7,  "MEDIUM"),
    (5,  "MEDIUM"),
    (4,  "LOW"),
    (1,  "LOW"),
])
def test_get_risk_level(conf, expected):
    assert get_risk_level(conf) == expected


# ─── is_placeholder ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("changeme",    True),
    ("test",        True),
    ("<password>",  True),
    ("${SECRET}",   True),
    ("%(pass)s",    True),
    ("abc",         True),   # under 4 chars
    ("****",        True),   # all stars
    ("xxxx",        True),   # all x
    ("realSecret9!", False),
    ("MyP@ssw0rd",  False),
])
def test_is_placeholder(value, expected):
    assert is_placeholder(value) == expected


# ─── is_placeholder_match ─────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("password = changeme",       True),
    ("api_key = test",            True),
    ("password = MySecretP@ss!", False),
    ("no_equals_here",            False),
])
def test_is_placeholder_match(text, expected):
    # is_placeholder_match extracts the value after = or : and delegates to
    # is_placeholder.  Template forms like <key> or ${VAR} are excluded from
    # capture by the regex (they contain < > { }) and would never reach this
    # function in practice — those chars are not matched by any pattern value regex.
    assert is_placeholder_match(text) == expected


# ─── is_docs_path ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path,expected", [
    ("/share/docs/deploy.ps1",                True),
    ("/share/examples/sample.json",           True),
    ("/share/tests/fixture.ps1",              True),
    ("/share/production/deploy.ps1",          False),
    ("/share/docs_archive/deploy.ps1",        False),   # substring only — must not match
    ("/share/documentation_team/script.ps1",  False),   # substring only — must not match
    (r"\\server\share\docs\creds.txt",        True),
])
def test_is_docs_path(path, expected):
    assert is_docs_path(path) == expected


# ─── scan_content ─────────────────────────────────────────────────────────────

def test_scan_content_detects_aws_key():
    content = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"  # AKIA + exactly 16 chars
    results = scan_content(content, "/some/script.sh")
    ids = [r["id"] for r in results]
    assert "aws_access_key" in ids


def test_scan_content_detects_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    results = scan_content(content, "/keys/id_rsa")
    ids = [r["id"] for r in results]
    assert "private_key_header" in ids


def test_scan_content_skips_placeholder():
    content = "password = changeme"
    results = scan_content(content, "/config/app.conf")
    # should produce no findings because value is a placeholder
    assert results == []


def test_scan_content_reduces_confidence_in_docs():
    content = "password = 'RealPassword123!'"
    results_normal = scan_content(content, "/prod/config.ps1")
    results_docs   = scan_content(content, "/docs/example.ps1")
    conf_normal = next(r["confidence"] for r in results_normal if r["id"] == "plaintext_password")
    conf_docs   = next(r["confidence"] for r in results_docs   if r["id"] == "plaintext_password")
    assert conf_docs < conf_normal


def test_scan_content_returns_match_lines():
    content = "line1\npassword = 'SecurePass1!'\nline3"
    results = scan_content(content, "/test/file.conf")
    pw = next((r for r in results if r["id"] == "plaintext_password"), None)
    assert pw is not None
    assert pw["matchLine"] == 2
    assert pw["matchCount"] >= 1


def test_scan_content_counts_multiple_occurrences():
    content = (
        "password = 'FirstSecret!'\n"
        "password = 'SecondSecret!'\n"
    )
    results = scan_content(content, "/test/multi.conf")
    pw = next((r for r in results if r["id"] == "plaintext_password"), None)
    assert pw is not None
    assert pw["matchCount"] == 2
    assert len(pw["allMatchLines"]) == 2


def test_scan_content_empty_is_empty():
    assert scan_content("", "/empty.txt") == []


# ─── build_finding ────────────────────────────────────────────────────────────

def _make_finding(**kwargs):
    defaults = dict(
        path="/some/file.ps1",
        ext=".ps1",
        size_bytes=1024,
        last_modified="2024-01-01 12:00",
        last_accessed="2024-01-01 12:00",
        owner="admin",
        matched_patterns=[],
        risky_name=False,
        binary_risk=False,
    )
    defaults.update(kwargs)
    return build_finding(**defaults)


def test_build_finding_returns_none_with_no_signals():
    assert _make_finding() is None


def test_build_finding_binary_risk():
    f = _make_finding(ext=".kdbx", binary_risk=True)
    assert f is not None
    assert f["riskLevel"] == "HIGH"
    ids = [x["id"] for x in f["findingsDetail"]]
    assert "sensitive_file_type" in ids


def test_build_finding_risky_name():
    f = _make_finding(risky_name=True)
    assert f is not None
    assert f["riskLevel"] == "MEDIUM"


def test_build_finding_hash_only_capped_low():
    patterns = [{"id": "md5_hash", "name": "MD5 Hash", "confidence": 3, "risk": "LOW"}]
    f = _make_finding(matched_patterns=patterns)
    assert f is not None
    assert f["hashOnly"] is True
    assert f["riskLevel"] == "LOW"
    assert f["confidence"] <= 4


def test_build_finding_no_findings_key():
    """findings joined-string field was removed — only findingsList should exist."""
    patterns = [{"id": "aws_access_key", "name": "AWS Access Key", "confidence": 9, "risk": "HIGH"}]
    f = _make_finding(matched_patterns=patterns)
    assert "findings" not in f
    assert "findingsList" in f
    assert "AWS Access Key" in f["findingsList"]


def test_build_finding_smb_meta():
    patterns = [{"id": "aws_access_key", "name": "AWS Access Key", "confidence": 9, "risk": "HIGH"}]
    meta = {"smbShare": r"\\server\share", "smbServer": "server", "smbRelativePath": "file.ps1"}
    f = _make_finding(matched_patterns=patterns, smb_meta=meta)
    assert f["smbShare"] == r"\\server\share"


# ─── load_suppressions / is_suppressed ───────────────────────────────────────

def test_load_suppressions_no_file():
    with tempfile.TemporaryDirectory() as d:
        result = load_suppressions(d)
    assert result == {"global": [], "patterns": {}}


def test_load_suppressions_global_and_section():
    content = "*.log\n[aws_access_key]\nscripts/deploy.ps1\n"
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, ".leaklensignore"), "w") as f:
            f.write(content)
        result = load_suppressions(d)
    assert "*.log" in result["global"]
    assert "scripts/deploy.ps1" in result["patterns"]["aws_access_key"]


def test_is_suppressed_global_glob():
    suppressions = {"global": ["*.log"], "patterns": {}}
    assert is_suppressed("/root/app.log", [], suppressions, "/root") is True
    assert is_suppressed("/root/app.ps1", [], suppressions, "/root") is False


def test_is_suppressed_pattern_specific():
    suppressions = {"global": [], "patterns": {"aws_access_key": ["scripts/*.ps1"]}}
    assert is_suppressed("/root/scripts/deploy.ps1", ["aws_access_key"], suppressions, "/root") is True
    assert is_suppressed("/root/scripts/deploy.ps1", ["plaintext_password"], suppressions, "/root") is False
