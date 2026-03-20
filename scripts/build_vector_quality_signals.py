#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "will",
    "into",
    "then",
    "because",
    "metric",
    "value",
    "data",
    "run",
    "agent",
}


def _load(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _safe_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _safe_write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    for t in TOKEN_RE.findall((text or "").lower()):
        if t not in STOPWORDS:
            out.append(t)
    return out


def _vec(text: str) -> Counter[str]:
    return Counter(_tokens(text))


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    if not a or not b:
        return 0.0
    keys = set(a.keys()) | set(b.keys())
    dot = sum(float(a.get(k, 0) * b.get(k, 0)) for k in keys)
    na = math.sqrt(sum(float(v * v) for v in a.values()))
    nb = math.sqrt(sum(float(v * v) for v in b.values()))
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (na * nb)))


def _pairwise_uniqueness(texts: list[str], near_dup_threshold: float = 0.92) -> dict[str, Any]:
    if len(texts) <= 1:
        return {"avg_cosine": 0.0, "near_dup_pairs": 0, "pair_count": 0, "uniqueness_score": 1.0}
    vecs = [_vec(t) for t in texts]
    sims: list[float] = []
    near_dup = 0
    for i in range(len(vecs)):
        for j in range(i + 1, len(vecs)):
            s = _cosine(vecs[i], vecs[j])
            sims.append(s)
            if s >= near_dup_threshold:
                near_dup += 1
    pair_count = len(sims)
    avg = (sum(sims) / pair_count) if pair_count else 0.0
    uniqueness = max(0.0, min(1.0, 1.0 - avg))
    return {
        "avg_cosine": round(avg, 4),
        "near_dup_pairs": near_dup,
        "pair_count": pair_count,
        "uniqueness_score": round(uniqueness, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build lightweight vector-style quality signals (deterministic, no heavy deps)")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_id = args.run_id
    doctor = _load(Path(f"data/agent_reports/{run_id}_doctor_variance.json")) or {}
    narrative = _load(Path(f"data/agent_reports/{run_id}_narrative_claims.json")) or {}

    portfolio = doctor.get("hypothesis_portfolio", []) if isinstance(doctor.get("hypothesis_portfolio"), list) else []
    hypotheses = [h for h in portfolio if isinstance(h, dict)]
    hyp_texts = [
        " ".join(
            [
                str(h.get("hypothesis_statement", "")).strip(),
                str(h.get("lever_type", "")).strip(),
                str(h.get("target_metric", "")).strip(),
            ]
        ).strip()
        for h in hypotheses
        if str(h.get("hypothesis_statement", "")).strip()
    ]

    claims = narrative.get("causal_chains", []) if isinstance(narrative.get("causal_chains"), list) else []
    if not claims and isinstance(narrative.get("claims"), list):
        claims = narrative.get("claims", [])
    claim_rows = [c for c in claims if isinstance(c, dict)]
    claim_texts = [
        " ".join(
            [
                str(c.get("observation", "")).strip(),
                str(c.get("root_cause_statement", "")).strip(),
                str(c.get("recommendation_next_step", "")).strip(),
                str(c.get("cause_type", "")).strip(),
            ]
        ).strip()
        for c in claim_rows
    ]

    hyp_uni = _pairwise_uniqueness(hyp_texts)
    claim_uni = _pairwise_uniqueness(claim_texts)

    refs_to_actions = 0
    for c in claim_rows:
        refs = c.get("evidence_refs", []) if isinstance(c.get("evidence_refs"), list) else []
        linked = False
        for ref in refs:
            if isinstance(ref, dict):
                src = str(ref.get("source", "")).strip().lower()
                if src in {"decision_trace", "commander", "doctor", "governance", "approvals"}:
                    linked = True
                    break
            else:
                txt = str(ref).lower()
                if any(k in txt for k in ("decision_trace", "commander_priority", "doctor_variance", "agent_approvals")):
                    linked = True
                    break
        if linked:
            refs_to_actions += 1
    action_link_rate = round(refs_to_actions / max(1, len(claim_rows)), 4)

    vector_quality_score = round(
        max(
            0.0,
            min(
                1.0,
                0.35 * float(hyp_uni["uniqueness_score"])
                + 0.35 * float(claim_uni["uniqueness_score"])
                + 0.30 * action_link_rate,
            ),
        ),
        4,
    )
    status = "PASS" if vector_quality_score >= 0.60 else "WARN"

    payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "lightweight_bow_cosine_v1",
        "inputs": {
            "hypothesis_count": len(hypotheses),
            "claim_count": len(claim_rows),
        },
        "hypothesis_semantic_uniqueness": hyp_uni,
        "claim_semantic_uniqueness": claim_uni,
        "action_linkage_rate": action_link_rate,
        "vector_quality_score": vector_quality_score,
        "status": status,
        "decision_authority": "none",
        "version": "vector_quality.v1",
    }

    out_json = Path(f"data/agent_reports/{run_id}_vector_quality.json")
    _safe_write_json(out_json, payload)

    md = [
        f"# Vector Quality Signals — {run_id}",
        "",
        "- Method: `lightweight_bow_cosine_v1` (deterministic, no external model/index).",
        "- Decision authority: `none` (advisory only).",
        f"- Score: `{vector_quality_score}` (`{status}`)",
        "",
        "## Signals",
        f"- hypothesis_uniqueness_score: `{hyp_uni['uniqueness_score']}`",
        f"- claim_uniqueness_score: `{claim_uni['uniqueness_score']}`",
        f"- action_linkage_rate: `{action_link_rate}`",
    ]
    out_md = Path(f"reports/L1_ops/{run_id}/vector_quality.md")
    _safe_write_md(out_md, "\n".join(md))

    print(f"ok: vector quality signals written for run_id={run_id}")


if __name__ == "__main__":
    main()
