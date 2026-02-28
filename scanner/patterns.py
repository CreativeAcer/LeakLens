# ─── Content patterns with confidence scoring ─────────────────────────────────
# confidence: 1-10  (1 = very likely false positive, 10 = near-certain credential)
# risk: derived from confidence (>=8 HIGH, >=5 MEDIUM, else LOW)

CONTENT_PATTERNS = [
    {
        "id": "plaintext_password",
        "name": "Plaintext Password",
        # Handles: password=value, password: value, "password": "value", 'password': 'value'
        "regex": r'''(?ix)(password|passwd|pwd)["\']?\s*[=:]\s*
            (?!(\s*["\']?\s*(
                changeme|placeholder|your[-_]?password|example|todo|
                fixme|test|dummy|none|null|false|true|\{\{|\*{3,}|x{3,}|
                <[^>]+>|\$\{|\%\(
            )))
            (?:"[^"\r\n]{4,}"|\'[^\'\r\n]{4,}\'|[^\s"\'<>{}]{4,})''',
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "connection_string",
        "name": "Connection String",
        "regex": r'(?i)(connectionstring|data\s+source|initial\s+catalog).*password\s*=',
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "ntlm_hash",
        "name": "NTLM Hash",
        "regex": r'\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b',
        "confidence": 7,
        "risk": "HIGH",
    },
    {
        "id": "md5_hash",
        "name": "MD5 Hash",
        "regex": r'\b[a-fA-F0-9]{32}\b',
        "confidence": 3,
        "risk": "LOW",
    },
    {
        "id": "sha1_hash",
        "name": "SHA1 Hash",
        "regex": r'\b[a-fA-F0-9]{40}\b',
        "confidence": 3,
        "risk": "LOW",
    },
    {
        "id": "sha256_hash",
        "name": "SHA256 Hash",
        "regex": r'\b[a-fA-F0-9]{64}\b',
        "confidence": 3,
        "risk": "LOW",
    },
    {
        "id": "sha512_hash",
        "name": "SHA512 Hash",
        "regex": r'\b[a-fA-F0-9]{128}\b',
        "confidence": 4,
        "risk": "LOW",
    },
    {
        "id": "bcrypt_hash",
        "name": "Bcrypt Hash",
        "regex": r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}',
        "confidence": 7,
        "risk": "HIGH",
    },
    {
        "id": "base64_credential",
        "name": "Base64 Credential",
        "regex": r'(?i)(password|secret|token|key)\s*[=:]\s*[A-Za-z0-9+/]{20,}={0,2}',
        "confidence": 7,
        "risk": "HIGH",
    },
    {
        "id": "aws_access_key",
        "name": "AWS Access Key",
        # AKIA + 16 alphanumeric (real key is 20 chars total); allow 14-18 to catch test/obfuscated keys
        "regex": r'\bAKIA[0-9A-Z]{14,18}\b',
        "confidence": 9,
        "risk": "HIGH",
    },
    {
        "id": "generic_api_key",
        "name": "Generic API Key/Token",
        "regex": r'(?i)(api[_-]?key|bearer|access[_-]?token)\s*[=:]\s*\S{10,}',
        "confidence": 6,
        "risk": "MEDIUM",
    },
    {
        "id": "bearer_token_value",
        "name": "Bearer Token",
        # Detects Bearer tokens used as values: Authorization: Bearer <token> or API_TOKEN = "Bearer eyJ..."
        "regex": r'(?i)Bearer\s+[A-Za-z0-9._\-+/=]{20,}',
        "confidence": 6,
        "risk": "MEDIUM",
    },
    {
        "id": "private_key_header",
        "name": "Private Key Header",
        "regex": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "confidence": 10,
        "risk": "HIGH",
    },
    {
        "id": "net_use_credential",
        "name": "Net Use Credential",
        "regex": r'(?i)net\s+use.*\/user:\S+',
        "confidence": 7,
        "risk": "HIGH",
    },
    {
        "id": "ps_secure_string",
        "name": "PowerShell SecureString",
        "regex": r'(?i)(ConvertTo-SecureString|ConvertFrom-SecureString)',
        "confidence": 6,
        "risk": "MEDIUM",
    },
    {
        "id": "hardcoded_pscredential",
        "name": "Hardcoded PSCredential",
        "regex": r'(?i)PSCredential\s*\(',
        "confidence": 6,
        "risk": "MEDIUM",
    },
    {
        "id": "sql_sa_password",
        "name": "SQL sa Password",
        "regex": r'(?i)(sa|sysadmin)\s+password\s*[=:]\s*\S+',
        "confidence": 8,
        "risk": "HIGH",
    },
]

# File extensions that are flagged regardless of content
FLAGGED_EXTENSIONS = {
    ".kdbx", ".kdb",
    ".pfx", ".p12",
    ".ppk",
    ".pem", ".key",
    ".jks",
    ".wallet",
}

# Filename substrings that mark suspicious files
FLAGGED_NAMES = [
    "password", "passwords", "passwd", "credentials", "creds",
    "secrets", "secret", "apikey", "api_key", "token",
    "serviceaccount", "svc_account", "wallet",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
]

# Exact filenames that are always suspicious
FLAGGED_EXACT_NAMES = {".env"}

# Text file extensions to scan for content
TARGET_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd",
    ".sh",
    ".txt", ".log",
    ".xml", ".config", ".conf",
    ".json", ".yaml", ".yml",
    ".ini", ".env",
    ".csv",
    ".sql",
    ".py", ".rb", ".php",
    ".md",
    ".htm", ".html",
}

# Common placeholder values — matches indicate likely false positive
PLACEHOLDER_VALUES = {
    "changeme", "password", "your_password", "yourpassword",
    "example", "test", "placeholder", "todo", "fixme",
    "dummy", "none", "null", "false", "true",
    "***", "xxx", "<password>", "${password}", "%(password)s",
    "testpassword", "samplepassword", "mypassword",
    "pass", "passwd", "enter_password", "yourpasswordhere",
    "secret123", "admin", "1234", "12345", "123456",
}

# Directory names that suggest docs/examples (reduces confidence by 3)
DOCS_DIRS = {
    "readme", "docs", "doc", "documentation",
    "examples", "example", "samples", "sample",
    "test", "tests", "fixtures", "mocks",
    "demo", "demos", "tutorial",
}

# Pattern IDs that are hash-only (low signal on their own — likely checksums, not credentials)
# NTLM hashes are always credential hashes so they are intentionally excluded here
HASH_PATTERN_IDS = {"md5_hash", "sha1_hash", "sha256_hash", "sha512_hash"}
