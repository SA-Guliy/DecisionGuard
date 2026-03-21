#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests


DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "qwen/qwen3-32b"
DEFAULT_PROMPT = "Hello world"


def _load_key_from_secrets_file(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "GROQ_API_KEY":
                return value.strip().strip("'").strip('"')
    except Exception as exc:
        print(f"[WARN] Failed reading {path}: {exc}")
    return ""


def _resolve_api_key(cli_key: str) -> tuple[str, str]:
    if cli_key.strip():
        return cli_key.strip(), "cli"
    env_key = os.getenv("GROQ_API_KEY", "").strip()
    if env_key:
        return env_key, "env:GROQ_API_KEY"
    secrets_path = Path.home() / ".groq_secrets"
    file_key = _load_key_from_secrets_file(secrets_path)
    if file_key:
        return file_key, f"file:{secrets_path}"
    return "", "missing"


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct connectivity check to Groq API (no project architecture layers).")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--timeout-sec", type=float, default=30.0)
    parser.add_argument("--api-key", default="", help="Optional key override. Otherwise uses env GROQ_API_KEY or ~/.groq_secrets")
    args = parser.parse_args()

    api_key, key_source = _resolve_api_key(args.api_key)
    print(f"[INFO] endpoint={args.endpoint}")
    print(f"[INFO] model={args.model}")
    print(f"[INFO] key_source={key_source}")

    if not api_key:
        print("[ERROR] GROQ_API_KEY is missing (env/cli/~/.groq_secrets).")
        return 2

    payload = {
        "model": args.model,
        "messages": [{"role": "user", "content": args.prompt}],
        "temperature": 0,
        "max_tokens": 64,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    print("[INFO] sending request...")
    try:
        response = requests.post(
            args.endpoint,
            headers=headers,
            json=payload,
            timeout=args.timeout_sec,
        )
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] request_exception_type={type(exc).__name__}")
        print(f"[ERROR] request_exception_raw={repr(exc)}")
        print(f"[ERROR] request_exception_text={exc}")
        return 1
    except Exception as exc:
        print(f"[ERROR] exception_type={type(exc).__name__}")
        print(f"[ERROR] exception_raw={repr(exc)}")
        print(f"[ERROR] exception_text={exc}")
        return 1

    print(f"[INFO] http_status={response.status_code}")
    print("[INFO] raw_response_body_start")
    print(response.text)
    print("[INFO] raw_response_body_end")

    if response.status_code >= 400:
        return 1

    try:
        body = response.json()
    except json.JSONDecodeError:
        print("[WARN] success status but response is not JSON.")
        return 0

    message = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    usage = body.get("usage", {})
    print(f"[INFO] assistant_message={message!r}")
    print(f"[INFO] usage={json.dumps(usage, ensure_ascii=False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
