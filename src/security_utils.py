from __future__ import annotations

import hashlib
import json
import fnmatch
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]

_QUERY_SECRET_KEYS = {
    "password",
    "pass",
    "pwd",
    "token",
    "apikey",
    "api_key",
    "secret",
    "key",
}

DEFAULT_MANIFEST_SCOPE_IGNORE_GLOBS: tuple[str, ...] = (
    "reports/L1_ops/*/artifact_manifest.json",
    "data/agent_quality/*_pre_publish_audit.json",
    "data/acceptance/*_acceptance.json",
)

RUN_SCOPE_JSON_GLOBS: tuple[str, ...] = (
    "reports/L1_ops/{run_id}/**/*.json",
    "data/llm_reports/{run_id}_*.json",
    "data/agent_reports/{run_id}_*.json",
    "data/ab_reports/{run_id}_*.json",
    "data/ab_preflight/{run_id}_*.json",
    "data/security_reports/*{run_id}*.json",
    "data/agent_quality/{run_id}_*.json",
    "data/agent_eval/{run_id}_*.json",
    "data/agent_governance/{run_id}_*.json",
    "data/governance/*{run_id}*.json",
    "data/decision_traces/*{run_id}*.json",
    "data/eval/*{run_id}*.json",
    "data/metrics_snapshots/{run_id}.json",
    "data/realism_reports/{run_id}_*.json",
)


def redact_text(value: str) -> str:
    out = str(value or "")
    for pattern, replacement in REDACTION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_exception_text(exc_text: str) -> str:
    return redact_text(exc_text)


def dsn_has_inline_credentials(dsn: str) -> bool:
    raw = str(dsn or "").strip()
    if not raw:
        return False
    if "service=" in raw:
        return False
    parsed = urlparse(raw)
    if parsed.scheme.lower().startswith("postgres"):
        if parsed.username or parsed.password:
            return True
        query = parse_qs(parsed.query, keep_blank_values=False)
        for k in query:
            if k.strip().lower() in _QUERY_SECRET_KEYS:
                return True
    return bool(re.search(r"://[^/\s:@]+:[^@/\s]+@", raw))


def enforce_no_inline_credentials(dsn: str, source_hint: str = "pg_dsn") -> None:
    if dsn_has_inline_credentials(dsn):
        raise SystemExit(
            f"Inline credentials are forbidden in DSN ({source_hint}). "
            "Use service-based connection (PGSERVICE + ~/.pgpass)."
        )


def enforce_service_dsn_policy(dsn: str, source_hint: str = "pg_dsn") -> None:
    raw = str(dsn or "").strip()
    if not raw:
        raise SystemExit(f"Missing DSN ({source_hint}). Use service-based connection (postgresql:///?service=<name>).")
    enforce_no_inline_credentials(raw, source_hint)
    if "service=" not in raw:
        raise SystemExit(
            f"Service-based DSN is required ({source_hint}). "
            "Use postgresql:///?service=<name> with ~/.pgpass."
        )


def sha256_hex_for_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_sidecar_path(path: Path) -> Path:
    return Path(f"{path}.sha256")


def write_sha256_sidecar(path: Path) -> str:
    digest = sha256_hex_for_path(path)
    sidecar = sha256_sidecar_path(path)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(digest + "\n", encoding="utf-8")
    return digest


def verify_sha256_sidecar(path: Path, *, required: bool) -> tuple[bool, str]:
    sidecar = sha256_sidecar_path(path)
    if not sidecar.exists():
        if required:
            return False, f"missing_integrity_sidecar:{sidecar}"
        return True, ""
    expected = sidecar.read_text(encoding="utf-8").strip().lower()
    if not expected:
        return False, f"invalid_integrity_sidecar:{sidecar}"
    actual = sha256_hex_for_path(path)
    if actual != expected:
        return False, f"integrity_mismatch:{path}"
    return True, ""


def _normalize_manifest_path(path: Path) -> str:
    p = Path(path)
    try:
        return str(p.relative_to(Path.cwd()))
    except Exception:
        return str(p)


def _path_matches_globs(path_str: str, globs: list[str] | tuple[str, ...]) -> bool:
    normalized = path_str.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, g.replace("\\", "/")) for g in globs if str(g).strip())


def _manifest_artifact_entry(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": _normalize_manifest_path(path),
        "size_bytes": int(st.st_size),
        "sha256": sha256_hex_for_path(path),
    }


def write_json_manifest(
    manifest_path: Path,
    artifact_paths: list[Path],
    *,
    run_id: str | None = None,
    version: str = "json_integrity_manifest.v1",
) -> dict[str, Any]:
    unique_paths: list[Path] = []
    seen: set[str] = set()
    for raw in artifact_paths:
        p = Path(raw)
        if not p.exists() or not p.is_file() or p.suffix.lower() != ".json":
            continue
        norm = _normalize_manifest_path(p)
        if norm in seen:
            continue
        seen.add(norm)
        unique_paths.append(p)

    payload: dict[str, Any] = {
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": str(run_id or "").strip() or None,
        "artifacts": [_manifest_artifact_entry(p) for p in unique_paths],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(manifest_path)
    return payload


def resolve_manifest_entry_path(manifest_path: Path, raw_path: str) -> Path:
    p = Path(str(raw_path or "").strip())
    if p.is_absolute() or p.exists():
        return p
    for base in manifest_path.parents:
        candidate = base / p
        if candidate.exists():
            return candidate
    return p


def verify_json_manifest(
    manifest_path: Path,
    *,
    require_manifest: bool = True,
    verify_manifest_sidecar: bool = True,
) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not manifest_path.exists():
        if require_manifest:
            return False, [f"missing_json_manifest:{manifest_path}"]
        return True, []

    if verify_manifest_sidecar:
        ok_manifest, reason_manifest = verify_sha256_sidecar(manifest_path, required=True)
        if not ok_manifest:
            issues.append(reason_manifest)

    payload: dict[str, Any]
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False, [*issues, f"invalid_json_manifest:{manifest_path}"]

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False, [*issues, f"empty_json_manifest:{manifest_path}"]

    for row in artifacts:
        if not isinstance(row, dict):
            issues.append("invalid_json_manifest_entry")
            continue
        path_raw = str(row.get("path", "")).strip()
        digest_expected = str(row.get("sha256", "")).strip().lower()
        size_expected = row.get("size_bytes")
        if not path_raw or not digest_expected:
            issues.append("invalid_json_manifest_entry")
            continue
        target = resolve_manifest_entry_path(manifest_path, path_raw)
        if not target.exists():
            issues.append(f"missing_manifest_artifact:{path_raw}")
            continue
        if target.suffix.lower() != ".json":
            issues.append(f"manifest_non_json_artifact:{path_raw}")
            continue
        if not isinstance(size_expected, int) or int(size_expected) < 0:
            issues.append(f"invalid_manifest_size:{path_raw}")
            continue
        if int(target.stat().st_size) != int(size_expected):
            issues.append(f"manifest_size_mismatch:{path_raw}")
            continue
        digest_actual = sha256_hex_for_path(target)
        if digest_actual != digest_expected:
            issues.append(f"manifest_sha256_mismatch:{path_raw}")

    return len(issues) == 0, issues


def json_paths_from_links_payload(links: dict[str, Any], *, include: list[Path] | None = None) -> list[Path]:
    out: list[Path] = []

    def _collect(raw: Any) -> None:
        if isinstance(raw, str) and raw.strip():
            p = Path(raw.strip())
            if p.suffix.lower() == ".json":
                out.append(p)
            return
        if isinstance(raw, list):
            for item in raw:
                _collect(item)
            return
        if isinstance(raw, dict):
            for item in raw.values():
                _collect(item)

    _collect(links.get("inputs"))
    _collect(links.get("outputs"))
    if include:
        out.extend(include)
    return out


def collect_run_scope_json_files(run_id: str) -> list[Path]:
    rid = str(run_id or "").strip()
    if not rid:
        return []
    out: set[str] = set()
    for pattern in RUN_SCOPE_JSON_GLOBS:
        glob_pattern = pattern.format(run_id=rid)
        for p in Path(".").glob(glob_pattern):
            if p.is_file() and p.suffix.lower() == ".json":
                out.add(_normalize_manifest_path(p))
    return [Path(p) for p in sorted(out)]


def verify_manifest_scope(
    manifest_path: Path,
    *,
    run_id: str,
    ignore_globs: list[str] | None = None,
    require_manifest: bool = True,
) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not manifest_path.exists():
        if require_manifest:
            return False, [f"missing_json_manifest:{manifest_path}"]
        return True, []
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False, [f"invalid_json_manifest:{manifest_path}"]

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        return False, [f"invalid_json_manifest:{manifest_path}"]

    manifest_entries: set[str] = set()
    for row in artifacts:
        if not isinstance(row, dict):
            continue
        raw_path = str(row.get("path", "")).strip()
        if not raw_path:
            continue
        resolved = resolve_manifest_entry_path(manifest_path, raw_path)
        manifest_entries.add(str(resolved.resolve()))

    ignore_patterns = list(DEFAULT_MANIFEST_SCOPE_IGNORE_GLOBS)
    if ignore_globs:
        ignore_patterns.extend(str(x) for x in ignore_globs if str(x).strip())

    for p in collect_run_scope_json_files(run_id):
        rel = _normalize_manifest_path(p)
        if _path_matches_globs(rel, ignore_patterns):
            continue
        resolved = str(p.resolve())
        if resolved not in manifest_entries:
            issues.append(f"extra_json_outside_manifest:{rel}")

    return len(issues) == 0, issues
