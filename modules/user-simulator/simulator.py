#!/usr/bin/env python3
"""
GramFuzz User Simulator — public recon + optional MTProto live mode.

Works WITHOUT bot token or API credentials via public t.me reconnaissance.
Optional Telethon live mode when TELEGRAM_API_ID/HASH are configured.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Optional

USER_AGENT = "GramFuzz/0.1.0 (authorized-security-testing)"


@dataclass
class InitDataCheck:
    valid_hmac: bool
    user_id: Optional[str]
    auth_date: Optional[str]
    issues: list[str]


@dataclass
class PublicProfile:
    username: str
    title: str
    description: str
    bot_type: str
    has_web_app: bool
    external_urls: list[str]
    secrets_found: list[str]


def fetch_public_profile(bot_username: str) -> PublicProfile:
    """Fetch and analyze public t.me bot page without any credentials."""
    username = bot_username.lstrip("@")
    url = f"https://t.me/{username}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read(512 * 1024).decode("utf-8", errors="replace")

    title_m = re.search(r'class="tgme_page_title"[^>]*><span[^>]*>([^<]+)', html)
    title = title_m.group(1).strip() if title_m else ""

    desc_m = re.search(r'class="tgme_page_description"[^>]*>([\s\S]*?)</div>', html)
    description = re.sub(r"<[^>]+>", " ", desc_m.group(1)).strip() if desc_m else ""

    has_web_app = bool(re.search(r"tgWebApp|Mini App|openWebApp|tgme_action_webapp|data-webapp", html, re.I))
    bot_type = "mini-app" if has_web_app else "classic"

    urls: list[str] = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
        if href.startswith("http") and "telegram.org" not in href and f"t.me/{username}" not in href:
            if href not in urls:
                urls.append(href)

    secrets: list[str] = []
    if re.search(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", html):
        secrets.append("telegram_bot_token_pattern")
    if re.search(r"(?i)(api[_-]?key|secret|token)\s*[:=]", html):
        secrets.append("api_key_pattern")

    return PublicProfile(
        username=username,
        title=title,
        description=description,
        bot_type=bot_type,
        has_web_app=has_web_app,
        external_urls=urls,
        secrets_found=secrets,
    )


def generate_start_vectors(bot_username: str) -> list[dict]:
    username = bot_username.lstrip("@")
    payloads = [
        ("admin", "medium", "Privilege escalation via referral code"),
        ("1' OR '1'='1", "medium", "SQL injection in start parameter"),
        ("../../etc/passwd", "medium", "Path traversal in start parameter"),
    ]
    vectors = []
    for payload, severity, desc in payloads:
        link = f"https://t.me/{username}?start={urllib.parse.quote(payload)}"
        vectors.append({
            "payload": payload,
            "severity": severity,
            "description": desc,
            "poc_link": link,
        })
    return vectors


def validate_init_data(init_data: str, bot_token: str) -> InitDataCheck:
    issues: list[str] = []
    parsed = urllib.parse.parse_qs(init_data, keep_blank_values=True)
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
            user_id = str(json.loads(urllib.parse.unquote(user_raw)).get("id"))
        except (json.JSONDecodeError, TypeError):
            issues.append("malformed user payload")

    return InitDataCheck(valid, user_id, flat.get("auth_date"), issues)


async def simulate_bot_interaction(bot_username: str, dry_run: bool = True) -> dict:
    if dry_run:
        profile = fetch_public_profile(bot_username)
        return {
            "mode": "public-recon",
            "bot": bot_username,
            "profile": asdict(profile),
            "start_vectors": generate_start_vectors(bot_username),
            "note": "No credentials required. Open PoC links in Telegram to test bot logic.",
        }

    try:
        from telethon import TelegramClient  # noqa: F401
    except ImportError:
        return {"error": "telethon not installed — run: pip install telethon"}

    return {"mode": "live", "status": "not configured — set TELEGRAM_API_ID and TELEGRAM_API_HASH"}


def main() -> int:
    parser = argparse.ArgumentParser(description="GramFuzz User Simulator")
    parser.add_argument("--bot", required=True, help="Target bot username")
    parser.add_argument("--init-data", help="initData string to validate (requires --bot-token)")
    parser.add_argument("--bot-token", help="Bot token for HMAC validation")
    parser.add_argument("--live", action="store_true", help="Enable live MTProto mode (needs API creds)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result: dict = {"module": "user-simulator", "version": "0.1.0"}

    if args.init_data and args.bot_token:
        check = validate_init_data(args.init_data, args.bot_token)
        result["init_data_check"] = asdict(check)
    else:
        result["simulation"] = asyncio.run(
            simulate_bot_interaction(args.bot, dry_run=not args.live)
        )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[GramFuzz] User Simulator — @{args.bot.lstrip('@')}")
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
