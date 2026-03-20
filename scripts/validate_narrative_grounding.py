#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_utils import write_sha256_sidecar

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]
BANNED_WORDS = {"материальное", "значимое", "вероятно", "возможно", "likely", "significant"}


def _redact(text: str) -> str:
    out = text
    for p, repl in REDACTION_PATTERNS:
        out = p.sub(repl, out)
    return out


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")
    if path.suffix.lower() == ".json":
        write_sha256_sidecar(path)


def _load(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _append_warning(md_path: Path, warning: str) -> None:
    if not md_path.exists():
        return
    txt = md_path.read_text(encoding="utf-8")
    if warning in txt:
        return
    md_path.write_text(f"{warning}\n\n{txt}", encoding="utf-8")


def _get_path(doc: dict[str, Any], path: str) -> Any:
    cur: Any = doc
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _f(v: Any) -> float | None:
    try:
        return float(v)
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate narrative grounding")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    md_path = out_dir / "CAUSAL_EXPLANATION.md"
    log_path = Path(f"data/logs/validate_narrative_grounding_{run_id}.log")

    try:
        claims_doc = _load(out_dir / "causal_claims.json") or _load(Path(f"data/agent_reports/{run_id}_narrative_claims.json")) or {}
        chains = claims_doc.get("causal_chains", []) if isinstance(claims_doc.get("causal_chains"), list) else []
        if not chains:
            chains = claims_doc.get("claims", []) if isinstance(claims_doc.get("claims"), list) else []

        evidence_pack = _load(out_dir / "evidence_pack.json") or {}
        ev = evidence_pack.get("evidence", {}) if isinstance(evidence_pack.get("evidence"), dict) else {}
        curr_snap = _load(Path(f"data/metrics_snapshots/{run_id}.json")) or {}
        prev_id = None
        mbr_meta = _load(out_dir / "mbr_meta.json") or {}
        if isinstance(mbr_meta, dict):
            prev_id = str(mbr_meta.get("prev_run_id_used", "") or "").strip() or None
        prev_snap = _load(Path(f"data/metrics_snapshots/{prev_id}.json")) if prev_id else {}
        curr_metrics = curr_snap.get("metrics", {}) if isinstance(curr_snap.get("metrics"), dict) else {}
        prev_metrics = (prev_snap or {}).get("metrics", {}) if isinstance((prev_snap or {}).get("metrics"), dict) else {}
        ab_doc = ev.get("ab_report", {}) if isinstance(ev.get("ab_report"), dict) else {}
        dq_doc = ev.get("dq_report", {}) if isinstance(ev.get("dq_report"), dict) else {}
        sb_doc = ev.get("synthetic_bias_report", {}) if isinstance(ev.get("synthetic_bias_report"), dict) else {}

        issues: list[str] = []
        for i, claim in enumerate(chains):
            if not isinstance(claim, dict):
                issues.append(f"claim_{i}:invalid_type")
                continue
            claim_id = str(claim.get("claim_id", f"C{i+1}"))
            metric = str(claim.get("metric", "")).strip()
            evidence = claim.get("evidence_refs", []) if isinstance(claim.get("evidence_refs"), list) else []
            if len(evidence) == 0:
                issues.append(f"{claim_id}:missing_evidence")
            for j, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    issues.append(f"{claim_id}:evidence_{j}:invalid")
                    continue
                source = str(ev.get("source", "")).strip()
                path = str(ev.get("path", "")).strip()
                if not source or not path:
                    issues.append(f"{claim_id}:evidence_{j}:missing_source_or_path")
                    continue
                if source in {"decision_trace", "approvals"}:
                    p = path.replace("artifact:", "").strip()
                    if not Path(p).exists():
                        issues.append(f"{claim_id}:evidence_{j}:path_not_found:{source}:{path}")
                    continue
                target = curr_snap
                if source == "metrics_snapshot_prev":
                    target = prev_snap or {}
                elif source in {"metrics_snapshot", "ab_report", "dq_report", "synthetic_bias"}:
                    if source == "metrics_snapshot":
                        target = curr_snap
                    elif source == "ab_report":
                        target = ab_doc
                    elif source == "dq_report":
                        target = dq_doc
                    else:
                        target = sb_doc
                val = _get_path(target if isinstance(target, dict) else {}, path)
                if val is None:
                    issues.append(f"{claim_id}:evidence_{j}:path_not_found:{source}:{path}")

            metric_now = _f(curr_metrics.get(metric))
            metric_prev = _f(prev_metrics.get(metric))
            claim_delta = _f(claim.get("delta_pct"))
            if metric and metric_now is not None and metric_prev is not None and metric_prev != 0 and claim_delta is not None:
                expected = ((metric_now - metric_prev) / metric_prev) * 100.0
                if abs(expected - claim_delta) > 0.5:
                    issues.append(f"{claim_id}:delta_mismatch:expected={expected:.3f}:claim={claim_delta:.3f}")

            conf = _f(claim.get("confidence"))
            if conf is not None and conf > 0.8 and len(evidence) < 2:
                issues.append(f"{claim_id}:high_confidence_needs_2_evidence")

        md_text = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
        for idx, paragraph in enumerate([p.strip() for p in md_text.split("\n\n") if p.strip()]):
            low = paragraph.lower()
            if any(w in low for w in BANNED_WORDS) and not re.search(r"[-+]?\d", paragraph):
                issues.append(f"paragraph_{idx}:banned_word_without_numeric_evidence")

        grounded = len(issues) == 0
        status = "GROUNDED" if grounded else "UNGROUNDED"
        if not grounded:
            _append_warning(md_path, "⚠️ UNGROUNDED CLAIMS DETECTED: claims are not fully backed by evidence.")

        commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
        commander = _load(commander_path) or {}
        if isinstance(commander, dict) and not grounded:
            dec = str(commander.get("normalized_decision", commander.get("decision", ""))).upper()
            if dec in {"RUN_AB", "ROLLOUT_CANDIDATE", "GO"}:
                commander["decision"] = "HOLD_RISK"
                commander["normalized_decision"] = "HOLD_RISK"
                blocked = commander.get("blocked_by", []) if isinstance(commander.get("blocked_by"), list) else []
                if "ungrounded_claims_detected" not in blocked:
                    blocked.append("ungrounded_claims_detected")
                commander["blocked_by"] = sorted({str(x) for x in blocked if str(x).strip()})[:20]
                _safe_write(commander_path, json.dumps(commander, ensure_ascii=False, indent=2))

        payload = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "narrative_status": status,
            "grounded": grounded,
            "issues": issues,
            "version": "narrative_grounding.v1",
        }
        out_json = out_dir / "causal_claims_validation.json"
        _safe_write(out_json, json.dumps(payload, ensure_ascii=False, indent=2))
        print(f"ok: narrative grounding status={status}")
    except Exception:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        print(f"ok: narrative grounding fallback. see {log_path}")


if __name__ == "__main__":
    main()
