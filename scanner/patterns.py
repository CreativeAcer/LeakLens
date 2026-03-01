import re

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
        "confidence": 8,
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
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "base64_credential",
        "name": "Base64 Credential",
        # Lowered to 5 — base64 near a keyword is ambiguous (session IDs, checksums, etc.)
        "regex": r'(?i)(password|secret|token|key)\s*[=:]\s*[A-Za-z0-9+/]{20,}={0,2}',
        "confidence": 5,
        "risk": "MEDIUM",
    },
    {
        "id": "aws_access_key",
        "name": "AWS Access Key",
        # Real AWS access keys are always exactly 20 chars: AKIA + 16 uppercase alphanumeric
        "regex": r'\bAKIA[0-9A-Z]{16}\b',
        "confidence": 9,
        "risk": "HIGH",
    },
    {
        "id": "generic_api_key",
        "name": "Generic API Key/Token",
        # Minimum 20 chars to reduce noise; placeholder lookahead added; bearer removed (covered by bearer_token_value)
        "regex": r'(?i)(api[_-]?key|access[_-]?token)\s*[=:]\s*(?!["\']?\s*(changeme|test|example|placeholder|dummy|none|null|\*{3,}|<[^>]+>))["\']?\S{20,}["\']?',
        "confidence": 6,
        "risk": "MEDIUM",
    },
    {
        "id": "bearer_token_value",
        "name": "Bearer Token",
        # Detects Bearer tokens used as values: Authorization: Bearer <token> or TOKEN = "Bearer eyJ..."
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
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "ps_secure_string",
        "name": "PowerShell SecureString",
        # Only fires when a string literal is hardcoded — not on legitimate Read-Host or pipeline usage
        "regex": r'(?i)ConvertTo-SecureString\s+["\'][^"\']{4,}["\']',
        "confidence": 8,
        "risk": "HIGH",
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
    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token",
        # ghp_ = classic PAT, gho_ = OAuth token, ghs_ = GitHub Actions secret
        "regex": r'\b(ghp_|gho_|ghs_)[A-Za-z0-9]{36}\b',
        "confidence": 10,
        "risk": "HIGH",
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token",
        "regex": r'\bglpat-[A-Za-z0-9\-_]{20}\b',
        "confidence": 10,
        "risk": "HIGH",
    },
    {
        "id": "azure_client_secret",
        "name": "Azure Client Secret",
        "regex": r'(?i)(client[_-]?secret|clientsecret)\s*[=:]\s*["\']?[A-Za-z0-9\-._~]{34,40}["\']?',
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "azure_storage_key",
        "name": "Azure Storage Account Key",
        # Storage account keys are 88-char base64 strings ending in ==.
        # Keyword anchor required — bare base64 matches every TLS cert and JWT payload.
        "regex": r'(?i)(AccountKey|StorageKey|storage[_-]?account[_-]?key)\s*[=:]\s*[A-Za-z0-9+/]{86}==',
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "dpapi_blob",
        "name": "DPAPI Encrypted Blob",
        # AQAAANCMnd8BFdERjHoAwE is the base64-encoded header of every DPAPI blob
        # 01000000d08c9ddf is the same header in hex — presence on a share means it was exported
        "regex": r'(?i)(AQAAANCMnd8BFdERjHoAwE|01000000d08c9ddf)',
        "confidence": 8,
        "risk": "HIGH",
    },
    {
        "id": "stripe_key",
        "name": "Stripe API Key",
        # sk_live_ = production secret key, sk_test_ = test secret key
        "regex": r'\bsk_(live|test)_[A-Za-z0-9]{24,}\b',
        "confidence": 10,
        "risk": "HIGH",
    },
    {
        "id": "slack_token",
        "name": "Slack Token",
        # xoxb = bot token, xoxa = app token, xoxp = user token, xoxs = workspace token
        "regex": r'\bxox[abps]-[0-9A-Za-z-]{10,}\b',
        "confidence": 10,
        "risk": "HIGH",
    },
    {
        "id": "sendgrid_key",
        "name": "SendGrid API Key",
        # SendGrid keys: SG. + ~22 base64url chars + . + ~43 base64url chars
        "regex": r'\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b',
        "confidence": 10,
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

# Common placeholder values — post-match filter applied across all patterns in the engine
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
# Matched as exact path segments only — not as substrings of longer names
DOCS_DIRS = {
    "readme", "docs", "doc", "documentation",
    "examples", "example", "samples", "sample",
    "test", "tests", "fixtures", "mocks",
    "demo", "demos", "tutorial",
}

# Pattern IDs that are hash-only (low signal on their own — likely checksums, not credentials)
# NTLM hashes are always credential hashes so they are intentionally excluded here
HASH_PATTERN_IDS = {"md5_hash", "sha1_hash", "sha256_hash", "sha512_hash"}

# Filenames to skip content scanning — lockfiles and build artifacts are full of
# hashes and base64 strings that produce massive hash-pattern noise with zero signal.
EXCLUDED_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "gemfile.lock", "pipfile.lock", "poetry.lock",
    "composer.lock", "cargo.lock", "packages.lock.json", "paket.lock",
}

# Pre-compiled patterns — use these in the engine to avoid re-compiling on every file.
# Inline flags in each regex string ((?i), (?ix), etc.) are preserved by re.compile().
COMPILED_PATTERNS = [
    {**p, "regex": re.compile(p["regex"])}
    for p in CONTENT_PATTERNS
]
