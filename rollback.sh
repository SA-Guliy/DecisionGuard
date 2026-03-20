#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

if [[ -x "_PROJECT_TRASH/rollback.sh" ]]; then
  echo "Running quarantine rollback from _PROJECT_TRASH/rollback.sh"
  "_PROJECT_TRASH/rollback.sh"
  exit 0
fi

echo "No generated rollback script found in _PROJECT_TRASH/rollback.sh"
echo "Nothing to rollback."

