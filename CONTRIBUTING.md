# Contributing to LeakLens

Thanks for your interest in contributing to LeakLens!

Whether you're fixing a typo, adding a detection pattern, or improving performance — your help makes this tool better for everyone.

LeakLens focuses on finding exposed credentials on file shares and local paths, a different attack surface than Git-based scanners. Contributions that improve detection quality, performance, and usability are especially welcome.

---

## Ways to Contribute

| Area | Description |
|------|-------------|
| 🧠 Detection patterns | Add new regex rules to catch more credential types |
| 🎯 Confidence scoring | Improve scoring logic and reduce false positives |
| 🐛 Bug fixes | Track down and squash unexpected behaviour |
| ⚡ Performance | Improve scan speed or reduce memory usage |
| 🖥️ Web UI | Enhance filtering, UX, or reporting features |
| 🧪 Tests | Add or improve test coverage |
| 📚 Documentation | Improve docs, examples, and onboarding |

---

## Development Setup

```bash
git clone https://github.com/CreativeAcer/LeakLens.git
cd LeakLens

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run LeakLens
python leaklens.py
```

The web UI will be available at **http://127.0.0.1:3000**

---

## Running Tests

```bash
python -m pytest tests/ -v
```

> All new detection patterns must include tests.

---

## Adding a New Detection Pattern

Detection rules live in `scanner/patterns.py`.

Each pattern must include:

- A clear name / ID
- A compiled regex
- A confidence score (1–10)
- A short description

### Pattern Guidelines

**Good patterns:**
- Anchor to context keywords where possible (e.g. `password=`, `api_key=`)
- Avoid overly generic regexes that match random strings
- Prefer higher precision over high recall

**Bad patterns:**
- Raw base64 or hex without surrounding context
- Hash-only matches without keyword proximity

### Tests Required

Add tests to `tests/test_patterns.py`. Each pattern must include:

- At least one positive match
- At least one negative case
- A realistic example payload

---

## Confidence Scoring Philosophy

LeakLens uses confidence scoring to reduce alert fatigue:

| Score | Signal |
|-------|--------|
| 9–10 | Near-certain secrets (private keys, cloud keys, tokens) |
| 7–8 | High confidence (plaintext passwords, NTLM hashes, connection strings) |
| 5–6 | Suspicious but contextual (API key patterns, PSCredential) |
| 1–4 | Low-signal indicators (hash strings, weak heuristics) |

If you add or modify a pattern, please justify the confidence score in your PR description.

### False-Positive Reduction

LeakLens deliberately downgrades confidence for:

- Files under `docs/`, `examples/`, `test/`
- Placeholder values (`changeme`, `example`, `${PASSWORD}`)
- Lockfiles and dependency manifests

If your change increases false positives, explain why the tradeoff is acceptable.

---

## Performance Considerations

LeakLens scans large SMB shares. Please keep in mind:

- Avoid reading entire files into memory if streaming is possible
- Regex patterns should be efficient and anchored where possible
- Do not add network calls in the scan loop
- Heavy computation should happen in worker threads, not the UI thread

---

## UI Contributions

Frontend files live in `frontend/`.

Contributions that improve filtering, sorting, result browsing, accessibility, or report navigation are very welcome. Keep dependencies minimal.

---

## Pull Request Guidelines

- One logical change per PR
- Include before/after behaviour in the PR description
- Add or update tests for detection logic changes
- Keep formatting and naming consistent with the existing codebase
- If adding new patterns, update documentation where relevant

---

## Reporting Bugs

If you find a bug:

- Include OS, Python version, and LeakLens version
- Provide a minimal reproduction if possible
- Include sample file content (sanitized) when reporting detection issues

---

## Code of Conduct

Be respectful. Security tooling attracts people from many backgrounds and skill levels.

Constructive feedback > dunking. Always.

---

Thanks for helping make LeakLens better!
