#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Post-acceptance non-critical Slack publisher.")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    webhook = str(os.getenv("SLACK_WEBHOOK_URL", "")).strip()
    acceptance_path = Path(f"data/acceptance/{args.run_id}_acceptance.json")
    if not webhook:
        print("skip: SLACK_WEBHOOK_URL not set")
        return
    if not acceptance_path.exists():
        print(f"skip: missing acceptance artifact {acceptance_path}")
        return
    payload = json.loads(acceptance_path.read_text(encoding="utf-8"))
    status = str(payload.get("overall_status", "UNKNOWN"))
    # Non-critical by design: no outbound dependency required here.
    print(f"skip: slack publish simulated run_id={args.run_id} status={status}")


if __name__ == "__main__":
    main()
