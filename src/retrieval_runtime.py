from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.architecture_v3 import load_json_with_integrity
from src.security_utils import sha256_sidecar_path, verify_sha256_sidecar

_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "metric",
    "metrics",
    "run",
    "config",
    "value",
}


def _tokenize(text: str) -> set[str]:
    tokens: set[str] = set()
    for token in _TOKEN_RE.findall(str(text or "").lower()):
        if token not in _STOPWORDS:
            tokens.add(token)
    return tokens


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _numeric_metrics(snapshot_payload: dict[str, Any]) -> dict[str, float]:
    metrics = snapshot_payload.get("metrics", {}) if isinstance(snapshot_payload.get("metrics"), dict) else {}
    out: dict[str, float] = {}
    for k, v in metrics.items():
        try:
            out[str(k)] = float(v)
        except Exception:
            continue
    return out


def _snapshot_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    run_cfg = payload.get("run_config", {}) if isinstance(payload.get("run_config"), dict) else {}
    for k, v in run_cfg.items():
        parts.append(f"{k}:{v}")
    metrics = _numeric_metrics(payload)
    for k in sorted(metrics.keys()):
        parts.append(f"{k}:{round(metrics[k], 6)}")
    return " ".join(parts)


def _artifact_ref(path: Path, suffix: str = "") -> str:
    base = f"artifact:{path}"
    if suffix:
        return f"{base}{suffix}"
    return base


def _extract_sha256(path: Path) -> str:
    sidecar = sha256_sidecar_path(path)
    if not sidecar.exists():
        return ""
    return sidecar.read_text(encoding="utf-8").strip().lower()


def build_semantic_hybrid_pack(
    *,
    run_id: str,
    top_k: int = 5,
    min_semantic_score: float = 0.08,
) -> tuple[dict[str, Any], str, list[str], list[str]]:
    now_iso = datetime.now(timezone.utc).isoformat()
    blocked_by: list[str] = []
    required_actions: list[str] = []
    error_code = "NONE"

    current_path = Path(f"data/metrics_snapshots/{run_id}.json")
    current = load_json_with_integrity(current_path)
    current_metrics = _numeric_metrics(current)
    current_tokens = _tokenize(_snapshot_text(current))
    if not current_metrics:
        return (
            {
                "version": "historical_context_pack_v1",
                "run_id": run_id,
                "generated_at": now_iso,
                "status": "FAIL",
                "retrieval_mode": "semantic_hybrid_mvp",
                "query_ref": _artifact_ref(current_path, "#/metrics"),
                "embedding_model": "token_jaccard_v1_mvp",
                "top_k": int(max(1, top_k)),
                "fact_refs": [],
                "evidence_hashes": [],
                "retrieval_policy": {
                    "top_k": int(max(1, top_k)),
                    "min_overlap_metrics": 1,
                    "source": "data/metrics_snapshots/*.json",
                },
                "rows": [],
                "error_code": "HISTORICAL_CONTEXT_MISSING",
                "blocked_by": ["current_metrics_snapshot_has_no_numeric_metrics"],
                "required_actions": ["ensure_metrics_snapshot_contains_numeric_metrics"],
            },
            "HISTORICAL_CONTEXT_MISSING",
            ["current_metrics_snapshot_has_no_numeric_metrics"],
            ["ensure_metrics_snapshot_contains_numeric_metrics"],
        )

    rows: list[dict[str, Any]] = []
    fact_refs: list[str] = [_artifact_ref(current_path, "#/metrics")]
    evidence_hashes: list[dict[str, str]] = []

    snapshots_dir = Path("data/metrics_snapshots")
    for candidate_path in sorted(snapshots_dir.glob("*.json")):
        candidate_run_id = candidate_path.stem.strip()
        if not candidate_run_id or candidate_run_id == run_id:
            continue
        try:
            candidate = load_json_with_integrity(candidate_path)
        except Exception:
            continue
        candidate_metrics = _numeric_metrics(candidate)
        if not candidate_metrics:
            continue
        candidate_tokens = _tokenize(_snapshot_text(candidate))
        semantic_score = _jaccard(current_tokens, candidate_tokens)
        overlap_keys = set(current_metrics.keys()) & set(candidate_metrics.keys())
        fact_score = len(overlap_keys) / max(1, len(set(current_metrics.keys()) | set(candidate_metrics.keys())))
        hybrid_score = 0.6 * semantic_score + 0.4 * fact_score
        if hybrid_score < float(min_semantic_score):
            continue

        candidate_fact_refs = [_artifact_ref(candidate_path, "#/metrics")]
        candidate_ab = sorted(Path("data/ab_reports").glob(f"{candidate_run_id}_*_ab_v2.json"))
        if candidate_ab:
            candidate_fact_refs.append(_artifact_ref(candidate_ab[0], "#/primary_metric"))
        elif sorted(Path("data/ab_reports").glob(f"{candidate_run_id}_*_ab.json")):
            candidate_fact_refs.append(_artifact_ref(sorted(Path("data/ab_reports").glob(f"{candidate_run_id}_*_ab.json"))[0], "#/summary"))

        rows.append(
            {
                "source_run_id": candidate_run_id,
                "similarity_score": round(hybrid_score, 6),
                "overlap_metric_count": int(len(overlap_keys)),
                "evidence_refs": candidate_fact_refs[:20],
                "summary": (
                    "semantic_hybrid_mvp "
                    f"semantic={round(semantic_score, 4)} "
                    f"fact={round(fact_score, 4)} "
                    f"overlap={len(overlap_keys)}"
                )[:500],
            }
        )
        fact_refs.extend(candidate_fact_refs)

    rows.sort(
        key=lambda row: (
            float(row.get("similarity_score", 0.0) or 0.0),
            int(row.get("overlap_metric_count", 0) or 0),
        ),
        reverse=True,
    )
    rows = rows[: int(max(1, top_k))]

    uniq_fact_refs: list[str] = []
    seen_refs: set[str] = set()
    for ref in fact_refs:
        clean = str(ref or "").strip()
        if not clean or clean in seen_refs:
            continue
        seen_refs.add(clean)
        uniq_fact_refs.append(clean)

    for ref in uniq_fact_refs:
        raw_path = str(ref)
        if raw_path.startswith("artifact:"):
            raw_path = raw_path[len("artifact:") :]
        if "#" in raw_path:
            raw_path = raw_path.split("#", 1)[0]
        path = Path(raw_path)
        if not path.exists():
            continue
        ok, _ = verify_sha256_sidecar(path, required=True)
        if not ok:
            error_code = "HISTORICAL_CONTEXT_INTEGRITY_FAIL"
            blocked_by.append(f"missing_or_invalid_sidecar:{path}")
            required_actions.append(f"regenerate_integrity_sidecar:{path}")
            continue
        sha = _extract_sha256(path)
        if not sha:
            error_code = "HISTORICAL_CONTEXT_INTEGRITY_FAIL"
            blocked_by.append(f"empty_sidecar_hash:{path}")
            required_actions.append(f"regenerate_integrity_sidecar:{path}")
            continue
        evidence_hashes.append({"artifact_ref": _artifact_ref(path), "sha256": sha})

    if not rows:
        if error_code == "NONE":
            error_code = "HISTORICAL_CONTEXT_MISSING"
        blocked_by.append("no_semantic_hybrid_hits")
        required_actions.append("expand_historical_corpus_or_adjust_query")

    if rows and (not uniq_fact_refs or not evidence_hashes):
        error_code = "HISTORICAL_CONTEXT_INTEGRITY_FAIL"
        blocked_by.append("fact_pull_or_integrity_missing")
        required_actions.append("repair_fact_refs_and_sidecars")

    status = "PASS" if rows and error_code == "NONE" and bool(evidence_hashes) else "FAIL"
    payload = {
        "version": "historical_context_pack_v1",
        "run_id": run_id,
        "generated_at": now_iso,
        "status": status,
        "retrieval_mode": "semantic_hybrid_mvp",
        "query_ref": _artifact_ref(current_path, "#/metrics"),
        "embedding_model": "token_jaccard_v1_mvp",
        "top_k": int(max(1, top_k)),
        "fact_refs": uniq_fact_refs[:100],
        "evidence_hashes": evidence_hashes[:100],
        "retrieval_policy": {
            "top_k": int(max(1, top_k)),
            "min_overlap_metrics": 1,
            "source": "data/metrics_snapshots/*.json",
        },
        "rows": rows,
        "error_code": error_code if error_code != "NONE" else "NONE",
        "blocked_by": sorted({x for x in blocked_by if str(x).strip()}),
        "required_actions": sorted({x for x in required_actions if str(x).strip()}),
    }
    return payload, str(payload.get("error_code", "NONE")), payload.get("blocked_by", []), payload.get("required_actions", [])
