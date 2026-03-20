#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"gsk_[A-Za-z0-9_\-]+"), "[REDACTED]"),
    (re.compile(r"postgresql://\S+"), "[REDACTED]"),
    (re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    out = text
    for pattern, repl in REDACTION_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_redact(text), encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _artifact_meta(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    data = path.read_bytes()
    st = path.stat()
    return {
        "path": str(path),
        "size_bytes": st.st_size,
        "mtime": st.st_mtime,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build grounded evidence pack for narrative analysis")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    out_dir = Path(f"reports/L1_ops/{run_id}")
    log_path = Path(f"data/logs/build_evidence_pack_{run_id}.log")
    try:
        metrics_path = Path(f"data/metrics_snapshots/{run_id}.json")
        doctor_path = Path(f"data/agent_reports/{run_id}_doctor_variance.json")
        evaluator_path = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
        commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
        bias_path = Path(f"data/realism_reports/{run_id}_synthetic_bias.json")
        links_path = Path(f"reports/L1_ops/{run_id}/links.json")
        mbr_meta_path = Path(f"reports/L1_ops/{run_id}/mbr_meta.json")
        cohort_pack_path = Path(f"reports/L1_ops/{run_id}/cohort_evidence_pack.json")

        metrics = _load_json(metrics_path)
        doctor = _load_json(doctor_path)
        evaluator = _load_json(evaluator_path)
        commander = _load_json(commander_path)
        synthetic_bias = _load_json(bias_path)
        links = _load_json(links_path)
        mbr_meta = _load_json(mbr_meta_path)
        cohort_pack = _load_json(cohort_pack_path)

        exp_id = ""
        if isinstance(metrics, dict):
            run_cfg = metrics.get("run_config", {})
            if isinstance(run_cfg, dict):
                exp_id = str(run_cfg.get("experiment_id", "")).strip()
        ab_path = Path(f"data/ab_reports/{run_id}_{exp_id}_ab.json") if exp_id else None
        ab = _load_json(ab_path) if isinstance(ab_path, Path) else None

        present = [
            x
            for x in [metrics, doctor, evaluator, commander, synthetic_bias, links, mbr_meta, ab, cohort_pack]
            if isinstance(x, dict)
        ]
        if not present:
            raise SystemExit("All evidence sources are missing")

        payload = {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sources": {
                "metrics_snapshot": str(metrics_path),
                "doctor": str(doctor_path),
                "evaluator": str(evaluator_path),
                "commander": str(commander_path),
                "synthetic_bias_audit": str(bias_path),
                "links": str(links_path),
                "retail_mbr_meta": str(mbr_meta_path),
                "cohort_evidence_pack": str(cohort_pack_path),
                "ab_report": (str(ab_path) if isinstance(ab_path, Path) else None),
            },
            "evidence": {
                "metrics_snapshot": metrics or {},
                "retail_mbr_meta": mbr_meta or {},
                "cohort_evidence_pack": cohort_pack or {},
                "ab_report": ab or {},
                "doctor": doctor or {},
                "evaluator": evaluator or {},
                "commander": commander or {},
                "synthetic_bias_audit": synthetic_bias or {},
                "links": links or {},
            },
            "artifact_meta": {
                "metrics_snapshot": _artifact_meta(metrics_path),
                "doctor": _artifact_meta(doctor_path),
                "evaluator": _artifact_meta(evaluator_path),
                "commander": _artifact_meta(commander_path),
                "synthetic_bias_audit": _artifact_meta(bias_path),
                "links": _artifact_meta(links_path),
                "retail_mbr_meta": _artifact_meta(mbr_meta_path),
                "cohort_evidence_pack": _artifact_meta(cohort_pack_path),
                "ab_report": (_artifact_meta(ab_path) if isinstance(ab_path, Path) else None),
            },
            "version": "evidence_pack.v1",
        }

        out_dir.mkdir(parents=True, exist_ok=True)
        out_json = out_dir / "evidence_pack.json"
        out_md = out_dir / "evidence_pack.md"
        _safe_write(out_json, json.dumps(payload, ensure_ascii=False, indent=2))
        md_lines = [
            f"# Evidence Pack — {run_id}",
            "",
            f"- generated_at: `{payload['generated_at']}`",
            f"- experiment_id: `{exp_id or 'missing'}`",
            f"- ab_status: `{((ab or {}).get('status') if isinstance(ab, dict) else 'missing')}`",
            f"- cohort_pack_status: `{((cohort_pack or {}).get('status') if isinstance(cohort_pack, dict) else 'missing')}`",
            f"- evaluator_decision: `{((evaluator or {}).get('decision') if isinstance(evaluator, dict) else 'missing')}`",
            f"- commander_decision: `{((commander or {}).get('normalized_decision', (commander or {}).get('decision')) if isinstance(commander, dict) else 'missing')}`",
            "",
            "## Sources",
        ]
        for k, v in payload["sources"].items():
            md_lines.append(f"- {k}: `{v}`")
        _safe_write(out_md, "\n".join(md_lines) + "\n")
        print(f"ok: evidence pack written for run_id={run_id}")
    except SystemExit:
        raise
    except Exception as exc:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(_redact(traceback.format_exc()), encoding="utf-8")
        _safe_write(
            out_dir / "EVIDENCE_PACK_ERROR.md",
            "\n".join(
                [
                    f"# Evidence Pack Error — {run_id}",
                    "",
                    f"- error: `{exc}`",
                    f"- log: `{log_path}`",
                    "",
                ]
            ),
        )
        raise SystemExit(f"evidence pack build failed. See {log_path}")


if __name__ == "__main__":
    main()
