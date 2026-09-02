# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in GramFuzz itself (not in targets scanned with it), please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email or DM the maintainer via GitHub: [@kiurakku](https://github.com/kiurakku).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within **72 hours** and provide a fix timeline within **7 days** for confirmed issues.

## Responsible Disclosure

We follow coordinated disclosure. We ask reporters to:

- Allow reasonable time for a fix before public disclosure
- Not exploit vulnerabilities beyond proof-of-concept
- Not access or modify data belonging to others

## GramFuzz Usage Policy

GramFuzz is an **offensive security tool** designed for **authorized testing only**.

### Permitted Use

- Penetration testing with written authorization from the system owner
- Security audits of your own Telegram bots and Mini Apps
- Research in controlled lab environments
- Educational purposes in authorized training contexts

### Prohibited Use

- Scanning systems without explicit written permission
- Using GramFuzz for unauthorized access, data theft, or disruption
- Deploying GramFuzz as a service against third-party targets without authorization
- Circumventing Telegram ToS for malicious purposes

Violations may result in legal action. The maintainers reserve the right to refuse support to users who violate this policy.

## Secrets & Credentials

Never commit the following to the repository:

- Telegram API credentials (`api_id`, `api_hash`)
- Bot tokens
- MTProto session files (`.session`)
- Private keys or wallet seeds
- `.env` files with real credentials

Use environment variables or local config files listed in `.gitignore`.

## Dependency Security

- Dependabot is configured for automated dependency updates
- CI runs `go vet`, `go test`, and vulnerability checks on every push
- Report supply-chain concerns through the same disclosure channel

## Hardening Recommendations for Deployments

If running GramFuzz in production/CI:

1. Run in isolated network segments
2. Use read-only filesystem where possible
3. Store credentials in a secrets manager (not plain env files)
4. Enable audit logging for all scan operations
5. Restrict report output directory permissions (`chmod 750`)
