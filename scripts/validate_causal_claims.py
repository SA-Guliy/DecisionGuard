#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Backward-compatible wrapper for narrative grounding validator")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    cmd = ["python3", "scripts/validate_narrative_grounding.py", "--run-id", args.run_id]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    # Non-fatal behavior preserved.
    raise SystemExit(0)


if __name__ == "__main__":
    main()
