# Security Policy

## Author & Contact

| | |
|---|---|
| **Project** | GramFuzz |
| **Author & Maintainer** | [kiurakku](https://github.com/kiurakku) (The Fear) |
| **Contact** | Telegram: [@thefear007](https://t.me/thefear007) |
| **Repository** | [github.com/kiurakku/GramFuzz](https://github.com/kiurakku/GramFuzz) |

For security-related inquiries, use Telegram **@thefear007**. Do not open public GitHub issues for vulnerabilities.

---

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

Security fixes are released for the latest minor version only.

---

## Reporting a Vulnerability

If you discover a security vulnerability **in GramFuzz itself** (not in targets scanned with the tool), please report it responsibly:

1. **Do NOT** open a public GitHub issue.
2. Contact the maintainer on Telegram: **[@thefear007](https://t.me/thefear007)**.
3. Include in your report:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact and affected components
   - Proof-of-concept (if available)
   - Suggested fix (optional)

### Response Timeline

| Stage | Target |
|---|---|
| Initial acknowledgment | Within 72 hours |
| Severity assessment | Within 5 business days |
| Fix timeline for confirmed issues | Within 7–14 days |
| Coordinated disclosure | After patch release |

---

## Responsible Disclosure

We follow coordinated disclosure practices. Reporters are asked to:

- Allow reasonable time for a fix before public disclosure
- Not exploit vulnerabilities beyond a minimal proof-of-concept
- Not access, modify, or exfiltrate data belonging to others
- Not perform testing against production systems without authorization

---

## GramFuzz Usage Policy

GramFuzz is an **offensive security tool** designed for **authorized testing only**.

### Permitted Use

- Penetration testing with **written authorization** from the system owner
- Security audits of **your own** Telegram bots and Mini Apps
- Research in **controlled lab environments**
- Educational use in **authorized training** contexts

### Prohibited Use

- Scanning any system without explicit written permission
- Using GramFuzz for unauthorized access, data theft, fraud, or disruption
- Operating GramFuzz as a public scanning service against third-party targets
- Circumventing Telegram Terms of Service for malicious purposes
- Any activity that violates applicable local, national, or international law

**Violations may result in legal action.** The maintainer reserves the right to refuse support and revoke access to anyone who violates this policy.

---

## Secrets & Credentials

Never commit the following to the repository or share them publicly:

| Secret | Risk |
|---|---|
| Telegram `api_id` / `api_hash` | Full MTProto account access |
| Bot tokens | Bot impersonation, initData forgery |
| MTProto `.session` files | Persistent account hijack |
| Private keys / wallet seeds | Financial loss |
| `.env` files with real credentials | Credential exposure |

Store secrets in environment variables or local files excluded by `.gitignore`. Use `.env.example` as a template only.

---

## Dependency Security

- **Dependabot** monitors Go, npm, pip, and GitHub Actions dependencies
- **CI** runs `go vet`, unit tests, and `govulncheck` on every push
- **Secret Scanning** and **Push Protection** are enabled on the repository
- Report supply-chain concerns via Telegram **@thefear007**

---

## Deployment Hardening

When running GramFuzz in CI or production environments:

1. Isolate scan traffic in a dedicated network segment
2. Use read-only filesystem mounts where possible
3. Store credentials in a secrets manager (Vault, GitHub Secrets, etc.)
4. Enable audit logging for all scan operations
5. Restrict report output directory permissions (`chmod 750`)
6. Rotate Telegram session files after each engagement
7. Never run live scans against production without a signed scope document

---

## Scope Document Recommendation

Before any engagement, maintain a written scope that includes:

- Target bot username(s) and Mini App URL(s)
- Backend API base URL(s)
- Allowed testing methods and time windows
- Excluded actions (e.g., DoS, social engineering)
- Emergency contact for the system owner

GramFuzz output reports are designed to support this documentation workflow.
