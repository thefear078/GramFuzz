#!/usr/bin/env python3
"""
GramFuzz AI Payload Analyzer — Local LLM analysis for attack vector generation.

Uses a locally hosted LLM (Qwen via LM Studio) to analyze request/response
context and generate contextual attack vectors without sending data to cloud.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def analyze_payload(
    request_context: dict[str, Any],
    response_context: dict[str, Any],
    endpoint: str = "http://localhost:1234/v1",
    model: str = "qwen2.5",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Analyze API payload context and suggest attack vectors."""
    vectors = [
        {"type": "role_escalation", "desc": "Mutate user role claim in JWT/session"},
        {"type": "id_substitution", "desc": "Replace user_id with adjacent IDs (BOLA/IDOR)"},
        {"type": "initdata_replay", "desc": "Replay captured initData with modified user field"},
        {"type": "tx_payload_swap", "desc": "Substitute transaction recipient before wallet sign"},
    ]

    result: dict[str, Any] = {
        "module": "ai-analyzer",
        "version": "0.1.0",
        "mode": "dry-run" if dry_run else "live",
        "endpoint_analyzed": endpoint if not dry_run else None,
        "attack_vectors": vectors,
    }

    if dry_run:
        result["note"] = "Dry-run — configure LM Studio endpoint for live LLM analysis."
        return result

    try:
        import urllib.request

        prompt = (
            f"Analyze this API interaction for security vulnerabilities.\n"
            f"Request: {json.dumps(request_context)}\n"
            f"Response: {json.dumps(response_context)}\n"
            f"Suggest attack vectors for authorized penetration testing."
        )

        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
        }).encode()

        req = urllib.request.Request(
            f"{endpoint}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            llm_response = json.loads(resp.read())
            result["llm_analysis"] = llm_response.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as exc:
        result["error"] = str(exc)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="GramFuzz AI Payload Analyzer")
    parser.add_argument("--endpoint", default="http://localhost:1234/v1", help="LLM API endpoint")
    parser.add_argument("--model", default="qwen2.5", help="Model name")
    parser.add_argument("--live", action="store_true", help="Enable live LLM analysis")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    result = analyze_payload({}, {}, endpoint=args.endpoint, model=args.model, dry_run=not args.live)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("[GramFuzz] AI Payload Analyzer")
        print(f"  Mode: {result['mode']}")
        print(f"  Attack vectors: {len(result['attack_vectors'])}")
        for v in result["attack_vectors"]:
            print(f"    • [{v['type']}] {v['desc']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
