# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Frostveil, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

**Contact:** security@your-org.example.com

You may optionally encrypt your report using PGP. Our public key is available at [keys.openpgp.org](https://keys.openpgp.org) under the security contact address above.

**Please include in your report:**

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce the issue, including any relevant environment details (OS, Python version, Frostveil version or commit).
- Any proof-of-concept code or output that demonstrates the issue.

**Disclosure Timeline:**

We follow a 90-day coordinated disclosure policy:

1. We will acknowledge receipt of your report within **5 business days**.
2. We will provide an initial assessment and severity estimate within **14 days**.
3. We aim to release a fix within **90 days** of the initial report. If a fix requires more time, we will communicate that to you with a revised timeline.
4. We will coordinate public disclosure with you. If you have a preferred disclosure date or venue, please include it in your report.

We will credit reporters in release notes unless you prefer to remain anonymous.

---

## Scope

The following classes of issues are in scope for this policy:

- **Code injection** — any input path that allows execution of unintended code (e.g., maliciously crafted browser profile data that triggers eval-like behavior in the extraction pipeline).
- **Path traversal** — inputs or configuration values that allow reading or writing files outside of intended directories.
- **Credential exposure in logs or output** — plaintext passwords, tokens, or other secrets appearing in log output, temporary files, or exported artifacts in a context where they should be protected.
- **DPAPI key leakage** — any code path that causes DPAPI master keys or derived encryption keys to be written to disk, logged, or transmitted.
- **Integrity bypass** — weaknesses in manifest signing or output bundle verification that allow an attacker to tamper with exported data without detection.
- **Insecure temporary file handling** — race conditions or permission issues in temporary database copy operations that could allow a local attacker to intercept sensitive data.

---

## Out of Scope

The following are not considered security vulnerabilities in Frostveil:

- **Credential extraction is intentional.** Frostveil is a browser forensics toolkit. Its core function is to extract and surface browser-stored credentials, cookies, history, and related artifacts from systems where the operator has authorization. The fact that the tool can read encrypted credentials is a feature, not a vulnerability.
- **Social engineering and phishing attacks** against users of the tool or their targets.
- **Attacks requiring physical access** to an already-compromised machine in a context indistinguishable from Frostveil's authorized use cases.
- **Vulnerabilities in third-party tools or browsers** that Frostveil reads data from. Report those to the respective projects.
- **Issues only reproducible on unsupported Python versions** (below 3.8).
- **Theoretical or speculative weaknesses** without a concrete proof of concept or demonstrated impact.

---

## Responsible Use

Frostveil is designed for **authorized forensic investigations, penetration testing engagements, and security research** conducted with explicit permission from the system owner or within a legal mandate.

Using Frostveil against systems you do not own or do not have explicit written authorization to test is illegal in most jurisdictions and is a violation of this project's intended use. The maintainers of Frostveil do not condone or support unauthorized access to computer systems.

By using this tool, you accept responsibility for ensuring your use is lawful and authorized.

---

## Security Design

Frostveil is designed with the following security properties to protect sensitive data encountered during forensic operations:

### DPAPI Key Handling

DPAPI master keys and derived decryption keys are held exclusively in memory during a session. They are never written to disk, included in log output, or embedded in exported artifacts. Key material is dereferenced and garbage-collected as soon as decryption is complete.

### Temporary Database Copies

Browser databases are never opened in place. `utils.safe_copy()` copies the target database to a controlled temporary location before any reads occur. Temporary copies are cleaned up immediately after extraction, regardless of whether the extraction succeeded or failed. Cleanup is performed in `finally` blocks to ensure it occurs even on unexpected errors.

### Encrypted Output Bundles

When artifact data is exported as an encrypted bundle, Frostveil uses **AES-256-GCM** for authenticated encryption. The GCM authentication tag provides both confidentiality and integrity — a tampered or corrupted bundle will be rejected on decryption rather than silently producing incorrect data.

### Manifest Signing

Export bundles include a signed manifest that records the artifact inventory, timestamps, and a cryptographic hash of the bundle contents. Manifest signing allows downstream consumers to verify that a bundle has not been altered since it was produced by Frostveil.

### Stealth Mode

When operating in stealth mode, Frostveil minimizes its forensic footprint on the target system:

- No files are written to the target system's user-accessible directories during extraction.
- Log output is suppressed or redirected to a controlled location.
- Temporary files use randomized names and are cleaned up immediately after use.
- No registry keys, scheduled tasks, or persistent artifacts are created on the target system.

Stealth mode is intended for authorized red team and incident response scenarios where minimizing examiner presence on the target is operationally necessary.
