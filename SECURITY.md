# Security Policy

LeakLens is a security tool. If you find a security vulnerability in LeakLens itself, please report it responsibly.

---

## Supported versions

Security fixes are applied to the latest release and `main` branch.

Older versions are not actively supported. Please upgrade to the latest release before reporting issues.

---

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, report privately:

- Open a GitHub Security Advisory (preferred)
  - Go to: https://github.com/CreativeAcer/LeakLens/security/advisories/new
- Or contact the maintainer directly via GitHub

Please include:

- LeakLens version
- OS and Python version
- Description of the vulnerability
- Impact (what an attacker could do)
- Proof-of-concept or reproduction steps (if safe to share)

---

## What counts as a security issue?

Examples:

- Remote code execution
- Path traversal
- Authentication bypass
- SMB credential leakage
- Unsafe deserialization
- Arbitrary file write/read
- XSS or injection in the web UI
- Sensitive data leakage in logs or reports

---

## Non-security issues

Please use GitHub Issues for:

- Feature requests
- False positives / detection tuning
- Performance problems
- UI bugs
- Documentation improvements

---

## Disclosure policy

LeakLens follows responsible disclosure:

1. Report is acknowledged within a reasonable timeframe
2. Issue is investigated and patched
3. Fix is released
4. Public disclosure happens after a fix is available

Please allow time for fixes before public discussion.

---

## Threat model (important context)

LeakLens:

- Reads file contents from SMB shares and local paths
- Processes potentially untrusted data
- Runs regex pattern matching on attacker-controlled input
- Streams results to a local web UI

The project assumes:

- The user is authorized to scan the target shares
- LeakLens runs on a trusted analyst machine
- The web UI is bound to localhost by default

If you identify ways a malicious file could:

- Crash the scanner
- Exhaust memory
- Trigger regex DoS
- Execute code
- Inject UI content

…please report it as a security issue.

---

## Safe usage reminder

LeakLens reads file contents and may store sensitive findings in reports and SQLite databases.

Users are responsible for:

- Protecting report files
- Securing the host running LeakLens
- Not committing scan outputs to version control
- Running scans only on systems they are authorized to access

---

Thanks for helping keep LeakLens safe for everyone. 🔐
