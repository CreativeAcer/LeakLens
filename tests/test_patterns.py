"""
Tests for scanner/patterns.py — each pattern has at least one positive
and one negative test string. Negatives must not produce a match.
"""
import re
import pytest
from scanner.patterns import COMPILED_PATTERNS, PLACEHOLDER_VALUES, CONTENT_PATTERNS


# ─── Structural sanity ────────────────────────────────────────────────────────

def test_all_patterns_compile():
    for p in COMPILED_PATTERNS:
        assert hasattr(p["regex"], "match"), f"Pattern {p['id']} not compiled"


def test_all_patterns_have_required_keys():
    required = {"id", "name", "regex", "confidence", "risk"}
    for p in CONTENT_PATTERNS:
        missing = required - p.keys()
        assert not missing, f"Pattern {p['id']} missing keys: {missing}"


def test_confidence_range():
    for p in CONTENT_PATTERNS:
        assert 1 <= p["confidence"] <= 10, f"Pattern {p['id']} confidence out of range"


def test_risk_matches_confidence():
    for p in CONTENT_PATTERNS:
        c = p["confidence"]
        expected = "HIGH" if c >= 8 else ("MEDIUM" if c >= 5 else "LOW")
        assert p["risk"] == expected, (
            f"Pattern {p['id']} risk={p['risk']} but confidence={c} implies {expected}"
        )


def test_placeholder_values_is_set():
    assert isinstance(PLACEHOLDER_VALUES, set)
    assert len(PLACEHOLDER_VALUES) > 5


# ─── Per-pattern positive / negative tests ────────────────────────────────────

@pytest.mark.parametrize("text,should_match", [
    # positives
    ('password = "SuperSecret99!"', True),
    ("password: 'mysecretpass'", True),
    ('"password": "letmein123"', True),
    # negatives
    ('password = ""', False),
    ('password = changeme', False),
    ('password = ${PASSWORD}', False),
    ('password = <your-password>', False),
    ('password = null', False),
])
def test_plaintext_password(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "plaintext_password")
    result = bool(pattern["regex"].search(text))
    assert result == should_match, f"plaintext_password {'should' if should_match else 'should not'} match: {text!r}"


@pytest.mark.parametrize("text,should_match", [
    ('connectionstring="Server=.;Database=Foo;password=hunter2"', True),
    ("data source=mydb;initial catalog=prod;password=abc", True),
    ("connectionstring=Server=myserver", False),
])
def test_connection_string(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "connection_string")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", True),
    ("aad3b435b51404eeaad3b435b51404ee", False),  # no colon separator → md5_hash, not ntlm
])
def test_ntlm_hash(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "ntlm_hash")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("d41d8cd98f00b204e9800998ecf8427e", True),
    ("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", False),  # non-hex
    ("d41d8cd98f00b204e9800998ecf8427e0", False),  # 33 chars
])
def test_md5_hash(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "md5_hash")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True),
    ("da39a3ee5e6b4b0d3255bfef95601890afd8070", False),  # 39 chars
])
def test_sha1_hash(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "sha1_hash")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", False),  # 63 chars
])
def test_sha256_hash(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "sha256_hash")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("$2b$12$KIXMv4N6gX5C3P7QnN8KpuJ8hQkTUaWv5V2Y1pFmHlK3sLdNeOXyW", True),
    ("$2b$12$short", False),
])
def test_bcrypt_hash(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "bcrypt_hash")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("secret = dGhpcyBpcyBhIHNlY3JldA==", True),
    ("token = c2VjcmV0dG9rZW5oZXJlMTIzNA==", True),
    ("token = abc", False),  # too short
])
def test_base64_credential(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "base64_credential")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("AKIAIOSFODNN7EXAMPLE", True),         # AKIA + exactly 16 chars = 20 total
    ("AKIAIOSFODNN7EXAMPL", False),         # AKIA + 15 — too short
    ("AKIAIOSFODNN7EXAMPLE1", False),       # AKIA + 17 — too long (\b breaks)
    ("akia1234567890abcdef", False),        # lowercase
])
def test_aws_access_key(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "aws_access_key")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("api_key = abcdefghijklmnopqrstu1234", True),
    ("API_KEY: ABCDEFGHIJKLMNOPQRSTU1234", True),
    ("access_token = mytoken12345678901234", True),
    ("api_key = test", False),       # too short
    ("api_key = changeme", False),   # placeholder
    ("api_key = example", False),    # placeholder
])
def test_generic_api_key(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "generic_api_key")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", True),
    ("token = Bearer abc123", False),  # too short value
])
def test_bearer_token(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "bearer_token_value")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("-----BEGIN RSA PRIVATE KEY-----", True),
    ("-----BEGIN PRIVATE KEY-----", True),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", True),
    ("-----BEGIN CERTIFICATE-----", False),
    ("-----END RSA PRIVATE KEY-----", False),
])
def test_private_key_header(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "private_key_header")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    (r"net use \\server\share /user:DOMAIN\user", True),
    ("net use z: /user:Administrator", True),
    ("net use /delete", False),
])
def test_net_use_credential(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "net_use_credential")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("ConvertTo-SecureString 'MyPlaintextPassword'", True),
    ('ConvertTo-SecureString "AnotherP@ssword"', True),
    ("ConvertTo-SecureString -String $inputPassword", False),  # no string literal
    ("ConvertFrom-SecureString $ss", False),  # wrong function
])
def test_ps_secure_string(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "ps_secure_string")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("New-Object PSCredential(", True),
    ("# PSCredential is a class", False),  # not followed by (
    # Note: [PSCredential]($user) uses cast syntax — the ( is after ], not PSCredential
])
def test_hardcoded_pscredential(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "hardcoded_pscredential")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("sa password = StrongPass1!", True),
    ("sysadmin password: secret123", True),
    ("sa password =", False),  # no value after = (needs \S+)
])
def test_sql_sa_password(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "sql_sa_password")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("ghp_" + "A" * 36, True),
    ("gho_" + "b" * 36, True),
    ("ghs_" + "C" * 36, True),
    ("ghp_" + "A" * 35, False),  # too short
    ("ghp_" + "A" * 37, False),  # too long — \b breaks it
    ("github_pat_12345678901234567890123456", False),  # wrong prefix
])
def test_github_pat(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "github_pat")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("glpat-abcdefghij1234567890", True),
    ("glpat-" + "x" * 20, True),
    ("glpat-short", False),
])
def test_gitlab_pat(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "gitlab_pat")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("client_secret = AbCdEfGhIjKlMnOpQrStUvWxYz12345678", True),
    ("clientSecret: xyz-abc_12345678901234567890123456", True),
    ("client_secret = abc", False),  # too short
])
def test_azure_client_secret(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "azure_client_secret")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("AccountKey=" + "A" * 86 + "==", True),
    ("StorageKey = " + "b" * 86 + "==", True),
    # bare base64 without keyword anchor — must NOT match
    ("A" * 86 + "==", False),
])
def test_azure_storage_key(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "azure_storage_key")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("AQAAANCMnd8BFdERjHoAwE/some/base64/data", True),
    ("01000000d08c9ddf0115d1118c7a00c04fc297eb", True),
    ("BQAAAAAAAAAAA", False),
])
def test_dpapi_blob(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "dpapi_blob")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("sk_live_" + "a" * 24, True),
    ("sk_test_" + "b" * 24, True),
    ("pk_live_" + "c" * 24, False),
])
def test_stripe_key(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "stripe_key")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("xoxb-1234567890-abcdefghijklmno", True),
    ("xoxa-987654321-ABCDEFGHIJKLMNO", True),
    ("xoxp-000000000-zzzzzzzzzzzzzzzz", True),
    ("xoxs-111111111-1234567890abcdef", True),
    ("xoxc-invalid", False),
])
def test_slack_token(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "slack_token")
    result = bool(pattern["regex"].search(text))
    assert result == should_match


@pytest.mark.parametrize("text,should_match", [
    ("SG." + "a" * 22 + "." + "b" * 43, True),
    ("SG.short.toolong", False),
])
def test_sendgrid_key(text, should_match):
    pattern = next(p for p in COMPILED_PATTERNS if p["id"] == "sendgrid_key")
    result = bool(pattern["regex"].search(text))
    assert result == should_match
