#!/usr/bin/env python3
"""
GramFuzz User Simulator — MTProto client for Telegram bot interaction.

Simulates human behavior in bot chats: sends commands, clicks inline buttons,
launches Mini Apps, and intercepts initData for backend validation testing.

Requires authorized testing credentials only.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import sys
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import parse_qs, unquote


@dataclass
class InitDataCheck:
    valid_hmac: bool
    user_id: Optional[str]
    auth_date: Optional[str]
    issues: list[str]


def validate_init_data(init_data: str, bot_token: str) -> InitDataCheck:
    """Validate Telegram WebApp initData HMAC signature."""
    issues: list[str] = []
    parsed = parse_qs(init_data, keep_blank_values=True)
    flat = {k: v[0] for k, v in parsed.items()}

    received_hash = flat.pop("hash", None)
    if not received_hash:
        return InitDataCheck(False, flat.get("user"), flat.get("auth_date"), ["missing hash field"])

    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(flat.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    computed = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    valid = hmac.compare_digest(computed, received_hash)
    if not valid:
        issues.append("HMAC mismatch — initData can be forged")

    user_raw = flat.get("user")
    user_id = None
    if user_raw:
        try:
            user_id = str(json.loads(unquote(user_raw)).get("id"))
        except (json.JSONDecodeError, TypeError):
            issues.append("malformed user payload")

    return InitDataCheck(valid, user_id, flat.get("auth_date"), issues)


async def simulate_bot_interaction(bot_username: str, dry_run: bool = True) -> dict:
    """Simulate bot interaction flow (dry-run without MTProto credentials)."""
    steps = [
        f"Connect MTProto session",
        f"Send /start to @{bot_username}",
        "Scan inline keyboard buttons",
        "Launch Web App if available",
        "Intercept initData payload",
    ]

    if dry_run:
        return {
            "mode": "dry-run",
            "bot": bot_username,
            "steps": steps,
            "note": "Configure TELEGRAM_API_ID, TELEGRAM_API_HASH, and session for live simulation.",
        }

    # Live mode requires Telethon — import lazily
    try:
        from telethon import TelegramClient  # noqa: F401
    except ImportError:
        return {"error": "telethon not installed — run: pip install telethon"}

    return {"mode": "live", "status": "not configured"}


def main() -> int:
    parser = argparse.ArgumentParser(description="GramFuzz User Simulator")
    parser.add_argument("--bot", required=True, help="Target bot username")
    parser.add_argument("--init-data", help="initData string to validate")
    parser.add_argument("--bot-token", help="Bot token for HMAC validation")
    parser.add_argument("--live", action="store_true", help="Enable live MTProto mode")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result: dict = {"module": "user-simulator", "version": "0.1.0"}

    if args.init_data and args.bot_token:
        check = validate_init_data(args.init_data, args.bot_token)
        result["init_data_check"] = asdict(check)
    else:
        result["simulation"] = asyncio.run(simulate_bot_interaction(args.bot, dry_run=not args.live))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[GramFuzz] User Simulator — @{args.bot}")
        for key, val in result.items():
            print(f"  {key}: {val}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
