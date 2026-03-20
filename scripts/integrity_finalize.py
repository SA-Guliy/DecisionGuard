#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_profile import load_security_profile
from src.security_utils import (
    collect_run_scope_json_files,
    json_paths_from_links_payload,
    verify_json_manifest,
    verify_manifest_scope,
    verify_sha256_sidecar,
    write_json_manifest,
)


def _load_links(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid_links_json:{path}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"invalid_links_payload:{path}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Finalize and verify artifact integrity manifest")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--security-profile", default="", help="Override security profile name")
    parser.add_argument(
        "--strict-manifest-scope",
        type=int,
        choices=[-1, 0, 1],
        default=-1,
        help="-1=from profile, 0=disable, 1=enable",
    )
    args = parser.parse_args()

    run_id = str(args.run_id or "").strip()
    if not run_id:
        raise SystemExit("missing_run_id")

    profile = load_security_profile(args.security_profile)
    require_manifest = bool(profile.get("require_json_manifest", True))
    strict_manifest_scope = bool(profile.get("strict_manifest_scope", True))
    if int(args.strict_manifest_scope) in {0, 1}:
        strict_manifest_scope = int(args.strict_manifest_scope) == 1

    out_dir = Path(f"reports/L1_ops/{run_id}")
    links_path = out_dir / "links.json"
    manifest_path = out_dir / "artifact_manifest.json"

    artifact_paths: list[Path] = []
    if links_path.exists():
        links_ok, links_reason = verify_sha256_sidecar(links_path, required=True)
        if not links_ok:
            raise SystemExit(f"links_integrity_error:{links_reason}")
        links = _load_links(links_path)
        artifact_paths = json_paths_from_links_payload(links, include=[links_path])
    elif require_manifest:
        raise SystemExit(f"missing_links_for_integrity_finalize:{links_path}")
    else:
        artifact_paths = collect_run_scope_json_files(run_id)

    if not artifact_paths:
        raise SystemExit("no_json_artifacts_for_manifest")

    write_json_manifest(manifest_path, artifact_paths, run_id=run_id)

    manifest_ok, manifest_issues = verify_json_manifest(
        manifest_path,
        require_manifest=True,
        verify_manifest_sidecar=True,
    )
    if not manifest_ok:
        issue = manifest_issues[0] if manifest_issues else "json_manifest_invalid"
        raise SystemExit(f"manifest_integrity_error:{issue}")

    if strict_manifest_scope:
        scope_ok, scope_issues = verify_manifest_scope(
            manifest_path,
            run_id=run_id,
            ignore_globs=profile.get("manifest_scope_ignore_globs", []),
            require_manifest=True,
        )
        if not scope_ok:
            issue = scope_issues[0] if scope_issues else "manifest_scope_invalid"
            raise SystemExit(f"manifest_scope_error:{issue}")

    print(
        f"ok: integrity_finalize run_id={run_id} profile={profile.get('name')} "
        f"manifest={manifest_path} artifacts={len(artifact_paths)} strict_scope={int(strict_manifest_scope)}"
    )


if __name__ == "__main__":
    main()
