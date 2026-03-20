#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.retrieval_v1 import build_doctor_decision_card, retrieve_similar_experiments


TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text or "")]


def _normalize(vec: list[float]) -> list[float]:
    import math

    norm = math.sqrt(sum(v * v for v in vec))
    if norm <= 0.0:
        return [0.0 for _ in vec]
    return [v / norm for v in vec]


def _vectorize(text: str, vocab: list[str]) -> list[float]:
    tf: dict[str, float] = {}
    for token in _tokenize(text):
        tf[token] = tf.get(token, 0.0) + 1.0
    return _normalize([tf.get(term, 0.0) for term in vocab])


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_synthetic_reports() -> list[dict[str, Any]]:
    return [
        {
            "experiment_id": "exp_hist_001",
            "hypothesis": "Raise free-shipping threshold to increase average basket size.",
            "primary_metric_outcome": {
                "metric_id": "aov",
                "control": 24.1,
                "treatment": 25.5,
                "delta_pct": 0.0581,
                "interpretation": "Local success on AOV",
            },
            "guardrail_breach": {
                "metric_id": "gp_margin",
                "control": 0.184,
                "treatment": 0.161,
                "delta_pct": -0.125,
                "breach_reason": "Margin diluted by aggressive discounts",
            },
            "reasoning_decision": {
                "decision": "STOP_ROLLOUT",
                "analyst_summary": "AOV improved, but margin erosion offset financial benefit.",
            },
        },
        {
            "experiment_id": "exp_hist_003",
            "hypothesis": "Speed up courier assignment to increase delivered orders per day.",
            "primary_metric_outcome": {
                "metric_id": "delivered_orders_per_day",
                "control": 4102,
                "treatment": 4311,
                "delta_pct": 0.0509,
                "interpretation": "Local operational success",
            },
            "guardrail_breach": {
                "metric_id": "oos_lost_gmv_rate",
                "control": 0.073,
                "treatment": 0.114,
                "delta_pct": 0.5616,
                "breach_reason": "Faster routing amplified stockout losses",
            },
            "reasoning_decision": {
                "decision": "HOLD_NEED_DATA",
                "analyst_summary": "Need inventory controls before scaling dispatch changes.",
            },
        },
        {
            "experiment_id": "exp_hist_004",
            "hypothesis": "Promote premium assortment in recommendations to lift gross merchandise value.",
            "primary_metric_outcome": {
                "metric_id": "gmv",
                "control": 1_220_000,
                "treatment": 1_297_000,
                "delta_pct": 0.0631,
                "interpretation": "Local growth success",
            },
            "guardrail_breach": {
                "metric_id": "fill_rate_units",
                "control": 0.931,
                "treatment": 0.887,
                "delta_pct": -0.0473,
                "breach_reason": "Premium SKU concentration hurt fulfillment availability",
            },
            "reasoning_decision": {
                "decision": "STOP_ROLLOUT",
                "analyst_summary": "Growth was not durable due to service degradation.",
            },
        },
    ]


def _build_doc_text(report: dict[str, Any]) -> str:
    p = report.get("primary_metric_outcome", {})
    g = report.get("guardrail_breach", {})
    r = report.get("reasoning_decision", {})
    return " ".join(
        [
            str(report.get("hypothesis", "")),
            f"primary_metric {p.get('metric_id')} delta_pct {p.get('delta_pct')}",
            f"guardrail_breach {g.get('metric_id')} delta_pct {g.get('delta_pct')}",
            str(g.get("breach_reason", "")),
            str(r.get("analyst_summary", "")),
            str(r.get("decision", "")),
        ]
    ).strip()


def _build_vector_index(reports: list[dict[str, Any]]) -> dict[str, Any]:
    docs: list[tuple[str, str]] = []
    vocab_set: set[str] = set()
    for row in reports:
        exp_id = str(row.get("experiment_id", "")).strip()
        doc_text = _build_doc_text(row)
        if not exp_id or not doc_text:
            continue
        docs.append((exp_id, doc_text))
        vocab_set.update(_tokenize(doc_text))

    vocab = sorted(vocab_set)
    vectors: list[dict[str, Any]] = []
    for exp_id, doc_text in docs:
        vectors.append({"experiment_id": exp_id, "vector": _vectorize(doc_text, vocab)})
    return {
        "version": "synthetic_history_vector_index.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vocab": vocab,
        "vectors": vectors,
    }


def build_batch_eval_cases(count: int = 20, *, dataset: str = "baseline") -> list[dict[str, Any]]:
    """Build synthetic batch-eval scenarios with expected risk label.

    `expected_block=True` means case should be blocked (STOP/HOLD).
    `expected_block=False` means case is expected safe enough to proceed (GO).
    """
    ds = str(dataset or "baseline").strip().lower()
    if ds not in {"baseline", "ood"}:
        raise ValueError(f"Unsupported batch dataset: {dataset}")
    if ds == "ood":
        risky_templates = [
            "Temporarily waive delivery fees for premium baskets to accelerate weekly top-line expansion.",
            "Compress picking buffers and dispatch windows to increase order flow during demand spikes.",
            "Broaden promotional depth on fragile categories to quickly recover demand velocity.",
            "Prioritize high-ticket bundles in ranking even when replenishment variance is elevated.",
            "Shorten stock cover targets to improve capital turnover under volatile supplier lead-times.",
        ]
        safe_templates = [
            "Improve on-page substitution guidance to reduce failed checkouts while keeping commercial policy unchanged.",
            "Refactor product taxonomy labels to improve discoverability with no intervention in pricing mechanics.",
            "Stabilize replenishment forecasting cadence while preserving existing promotion and service-level policies.",
            "Optimize search intent matching with phased rollout and explicit operational health monitoring.",
            "Enhance PDP content hierarchy to reduce decision friction without changing discount architecture.",
        ]
    else:
        risky_templates = [
            "Increase free-shipping threshold and discount pressure to raise AOV quickly despite tighter margin controls.",
            "Push premium assortment aggressively to lift GMV even if availability becomes unstable.",
            "Speed courier assignment and reduce picker slack to maximize throughput at peak hours.",
            "Run flash discounts on high-turnover SKUs to boost conversion this week.",
            "Expand coupon depth for reactivation campaigns to recover short-term demand.",
        ]
        safe_templates = [
            "Optimize recommendation ranking with no discount change and explicit margin floor monitoring.",
            "Improve product detail clarity to reduce returns while keeping pricing and shipping policy unchanged.",
            "Tune inventory reorder cadence to reduce stockouts without changing promo intensity.",
            "Refine checkout UX copy to improve completion while preserving current fulfillment constraints.",
            "Adjust assortment exposure gradually with hard guardrails on fill rate and margin.",
        ]

    cases: list[dict[str, Any]] = []
    i = 0
    while len(cases) < count:
        risk_txt = risky_templates[i % len(risky_templates)]
        safe_txt = safe_templates[i % len(safe_templates)]
        idx = len(cases) + 1
        cases.append(
            {
                "case_id": f"risk_{idx:03d}",
                "query": f"{risk_txt} Variant {i + 1}.",
                "expected_block": True,
                "profile": f"risky_{ds}",
            }
        )
        if len(cases) >= count:
            break
        idx = len(cases) + 1
        cases.append(
            {
                "case_id": f"safe_{idx:03d}",
                "query": f"{safe_txt} Variant {i + 1}.",
                "expected_block": False,
                "profile": f"safe_{ds}",
            }
        )
        i += 1
    return cases[:count]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic historical AB memory and run Sprint-1 retrieval POC.")
    parser.add_argument("--out-sot", default="data/poc/history_sot_v1.json")
    parser.add_argument("--out-index", default="data/poc/history_vector_index_v1.json")
    parser.add_argument("--run-demo", type=int, default=1, choices=[0, 1])
    parser.add_argument("--run-id", default="sprint1_poc")
    parser.add_argument(
        "--query",
        default=(
            "Increase recommendation pressure to raise GMV and conversion in checkout."
        ),
    )
    parser.add_argument("--top-k", type=int, default=1)
    parser.add_argument("--out-card", default="")
    parser.add_argument(
        "--doctor-backend",
        default="mock",
        choices=["mock", "auto", "groq", "ollama", "local_mock"],
    )
    parser.add_argument("--doctor-model", default="")
    args = parser.parse_args()

    reports = _build_synthetic_reports()
    sot_payload = {
        "version": "synthetic_history_sot.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": reports,
    }
    vector_index = _build_vector_index(reports)

    sot_path = Path(args.out_sot)
    index_path = Path(args.out_index)
    _save_json(sot_path, sot_payload)
    _save_json(index_path, vector_index)

    print(f"[ok] synthetic SoT saved: {sot_path} (reports={len(reports)})")
    print(f"[ok] vector index saved: {index_path} (vocab={len(vector_index.get('vocab', []))})")

    if int(args.run_demo) != 1:
        return

    matches = retrieve_similar_experiments(
        query_text=args.query,
        sot=sot_payload,
        vector_index=vector_index,
        top_k=args.top_k,
    )
    out_card = (
        Path(args.out_card)
        if str(args.out_card).strip()
        else Path(f"reports/L1_ops/{args.run_id}/POC_DECISION_CARD.md")
    )
    card = build_doctor_decision_card(
        run_id=args.run_id,
        query_text=args.query,
        matches=matches,
        out_path=out_card,
        doctor_backend=args.doctor_backend,
        doctor_model=args.doctor_model,
    )

    print("\n=== Sprint-1 Tracer Bullet (E2E) ===")
    if matches:
        top = matches[0]
        print(
            f"retrieval_top_match={top.experiment_id} similarity={top.score} "
            f"guardrail_breach={top.guardrail_breach.get('metric_id')}"
        )
    else:
        print("retrieval_top_match=none")
    print(f"doctor_backend={args.doctor_backend}")
    print("")
    print(card)
    print(f"\n[ok] Decision Card saved: {out_card}")


if __name__ == "__main__":
    main()
