#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm_client import get_llm_backend


TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "then",
    "were",
    "was",
    "are",
    "is",
    "our",
    "your",
    "them",
    "they",
    "their",
    "metric",
    "metrics",
    "test",
    "experiment",
    "ab",
    "a",
    "b",
}


@dataclass(frozen=True)
class RetrievalMatch:
    experiment_id: str
    score: float
    hypothesis: str
    primary_metric_outcome: dict[str, Any]
    guardrail_breach: dict[str, Any]
    reasoning_decision: dict[str, Any]


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    for token in TOKEN_RE.findall((text or "").lower()):
        if token not in STOPWORDS:
            out.append(token)
    return out


def _l2norm(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    if norm <= 0.0:
        return [0.0 for _ in vec]
    return [v / norm for v in vec]


def _vectorize_text(text: str, vocab: list[str]) -> list[float]:
    tf: dict[str, float] = {}
    for token in _tokenize(text):
        tf[token] = tf.get(token, 0.0) + 1.0
    vec = [tf.get(term, 0.0) for term in vocab]
    return _l2norm(vec)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return max(0.0, min(1.0, sum(x * y for x, y in zip(a, b))))


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mock_doctor_decision_card(
    *,
    run_id: str,
    query_text: str,
    matches: list[RetrievalMatch],
    generated_at_iso: str,
) -> str:
    if not matches:
        return "\n".join(
            [
                f"# One-Page Decision Card (Doctor POC) — {run_id}",
                "",
                f"- Generated at: `{generated_at_iso}`",
                f"- Query hypothesis: `{query_text}`",
                "- Decision: `HOLD_NEED_DATA`",
                "- Doctor backend: `mock`",
                "",
                "## Executive Summary",
                "No relevant historical analogue was found in the current memory set. "
                "Proceeding would rely on weak evidence and raises decision-risk.",
                "",
                "## Business Risk View",
                "- Local upside is unverified against second-order effects.",
                "- Historical context coverage is insufficient for safe insurance-grade decisioning.",
                "",
                "## Recommendation",
                "- Hold rollout and request additional comparable cases.",
                "- Re-run once historical context is expanded and reviewed by a human approver.",
            ]
        )

    top = matches[0]
    primary = top.primary_metric_outcome
    breach = top.guardrail_breach
    top_decision = str(top.reasoning_decision.get("decision", "HOLD_NEED_DATA")).upper()
    if top_decision in {"STOP_ROLLOUT", "STOP"} and float(top.score) >= 0.45:
        decision = "STOP_ROLLOUT"
    elif float(top.score) < 0.25:
        decision = "GO"
    else:
        decision = "HOLD_NEED_DATA"
    return "\n".join(
        [
            f"# One-Page Decision Card (Doctor POC) — {run_id}",
            "",
            f"- Generated at: `{generated_at_iso}`",
            f"- Query hypothesis: `{query_text}`",
            f"- Decision: `{decision}`",
            "- Doctor backend: `mock`",
            "",
            "## Executive Summary",
            f"The closest historical analogue (`{top.experiment_id}`, similarity `{top.score}`) "
            f"shows a classic false-success pattern: primary metric `{primary.get('metric_id')}` improved "
            f"(delta `{primary.get('delta_pct')}`), while guardrail `{breach.get('metric_id')}` deteriorated "
            f"(delta `{breach.get('delta_pct')}`).",
            "",
            "## Why This Matters (False Success Insurance)",
            "This indicates local optimization can hide systemic damage. "
            "If we scale now, we risk repeating a previously observed loss pattern.",
            "",
            "## Retrieved Historical Evidence",
            *[
                f"- `{m.experiment_id}` similarity=`{m.score}` primary_metric=`{m.primary_metric_outcome.get('metric_id')}` "
                f"guardrail_breach=`{m.guardrail_breach.get('metric_id')}`"
                for m in matches
            ],
            "",
            "## Recommendation",
            "- Block rollout for this hypothesis shape until mitigation controls are in place.",
            "- Run constrained follow-up with explicit guardrail monitoring and human approval.",
            "- Document mitigation hypothesis before requesting another rollout decision.",
        ]
    )


def _llm_doctor_decision_card(
    *,
    run_id: str,
    query_text: str,
    matches: list[RetrievalMatch],
    generated_at_iso: str,
    backend_name: str,
    model_name: str,
) -> str:
    compact_matches: list[dict[str, Any]] = []
    for m in matches:
        compact_matches.append(
            {
                "experiment_id": m.experiment_id,
                "similarity": m.score,
                "hypothesis": m.hypothesis,
                "primary_metric_outcome": m.primary_metric_outcome,
                "guardrail_breach": m.guardrail_breach,
                "reasoning_decision": m.reasoning_decision,
            }
        )

    system_prompt = (
        "You are Doctor, an executive decision analyst in an A/B governance engine. "
        "Write concise business-language output for C-level readers. "
        "Focus on false-success insurance, but apply Calculated Risk so safe iterations are not blocked."
    )
    user_prompt = (
        f"Create a one-page decision card in markdown for run_id={run_id}.\n"
        f"Generated_at={generated_at_iso}\n"
        f"Incoming hypothesis:\n{query_text}\n\n"
        "Retrieved historical evidence (JSON):\n"
        f"{json.dumps(compact_matches, ensure_ascii=False, indent=2)}\n\n"
        "Rules:\n"
        "- Provide sections: Executive Summary, Business Risk View, Retrieved Historical Evidence, Recommendation.\n"
        "- Decision must be STOP_ROLLOUT or HOLD_NEED_DATA or GO.\n"
        "- Choose STOP_ROLLOUT only for clear evidence of material guardrail harm.\n"
        "- If risk is theoretical/minor and business upside is clear, choose GO with monitoring.\n"
        "- Use human-readable business wording, not code-like phrasing.\n"
    )
    backend = get_llm_backend(backend_name, model_name or None)
    raw = backend.generate(user_prompt, system_prompt=system_prompt).strip()

    if raw.startswith("{") and raw.endswith("}"):
        # local_mock backend returns JSON not suitable for this card
        raise RuntimeError("LLM backend returned non-card JSON payload")
    if "Executive Summary" not in raw:
        raw = "\n".join(
            [
                f"# One-Page Decision Card (Doctor POC) — {run_id}",
                "",
                f"- Generated at: `{generated_at_iso}`",
                f"- Query hypothesis: `{query_text}`",
                "- Doctor backend: `api`",
                "",
                raw,
            ]
        )
    return raw


def retrieve_similar_experiments(
    *,
    query_text: str,
    sot: dict[str, Any],
    vector_index: dict[str, Any],
    top_k: int = 1,
) -> list[RetrievalMatch]:
    vocab = vector_index.get("vocab", [])
    if not isinstance(vocab, list) or not vocab:
        raise RuntimeError("Invalid vector index: missing vocab")
    query_vec = _vectorize_text(query_text, [str(v) for v in vocab])

    reports = sot.get("reports", [])
    if not isinstance(reports, list):
        raise RuntimeError("Invalid SoT: reports must be list")

    index_rows = vector_index.get("vectors", [])
    if not isinstance(index_rows, list):
        raise RuntimeError("Invalid vector index: vectors must be list")

    by_id: dict[str, dict[str, Any]] = {}
    for row in reports:
        if isinstance(row, dict):
            exp_id = str(row.get("experiment_id", "")).strip()
            if exp_id:
                by_id[exp_id] = row

    scored: list[tuple[str, float]] = []
    for row in index_rows:
        if not isinstance(row, dict):
            continue
        exp_id = str(row.get("experiment_id", "")).strip()
        vec = row.get("vector", [])
        if not exp_id or not isinstance(vec, list):
            continue
        try:
            doc_vec = [float(v) for v in vec]
        except Exception:
            continue
        scored.append((exp_id, _cosine_similarity(query_vec, doc_vec)))

    scored.sort(key=lambda x: x[1], reverse=True)
    out: list[RetrievalMatch] = []
    for exp_id, score in scored[: max(1, top_k)]:
        doc = by_id.get(exp_id, {})
        out.append(
            RetrievalMatch(
                experiment_id=exp_id,
                score=round(float(score), 4),
                hypothesis=str(doc.get("hypothesis", "")),
                primary_metric_outcome=doc.get("primary_metric_outcome", {})
                if isinstance(doc.get("primary_metric_outcome"), dict)
                else {},
                guardrail_breach=doc.get("guardrail_breach", {})
                if isinstance(doc.get("guardrail_breach"), dict)
                else {},
                reasoning_decision=doc.get("reasoning_decision", {})
                if isinstance(doc.get("reasoning_decision"), dict)
                else {},
            )
        )
    return out


def build_doctor_decision_card(
    *,
    run_id: str,
    query_text: str,
    matches: list[RetrievalMatch],
    out_path: Path,
    doctor_backend: str = "mock",
    doctor_model: str = "",
) -> str:
    generated_at_iso = datetime.now(timezone.utc).isoformat()
    backend_norm = str(doctor_backend or "mock").strip().lower()

    if backend_norm == "mock":
        md = _mock_doctor_decision_card(
            run_id=run_id,
            query_text=query_text,
            matches=matches,
            generated_at_iso=generated_at_iso,
        )
    else:
        try:
            md = _llm_doctor_decision_card(
                run_id=run_id,
                query_text=query_text,
                matches=matches,
                generated_at_iso=generated_at_iso,
                backend_name=backend_norm,
                model_name=str(doctor_model or "").strip(),
            )
        except Exception:
            md = _mock_doctor_decision_card(
                run_id=run_id,
                query_text=query_text,
                matches=matches,
                generated_at_iso=generated_at_iso,
            )

    _save_text(out_path, md)
    return md


def _run_cli() -> None:
    parser = argparse.ArgumentParser(description="Sprint-1 hybrid retrieval demo (semantic + structured SoT).")
    parser.add_argument("--sot-path", default="data/poc/history_sot_v1.json")
    parser.add_argument("--index-path", default="data/poc/history_vector_index_v1.json")
    parser.add_argument("--query", required=True, help="Incoming experiment hypothesis text")
    parser.add_argument("--top-k", type=int, default=1)
    parser.add_argument("--run-id", default="sprint1_poc")
    parser.add_argument("--out-card", default="")
    parser.add_argument(
        "--doctor-backend",
        default="mock",
        choices=["mock", "auto", "groq", "ollama", "local_mock"],
        help="Doctor text generation backend for decision card",
    )
    parser.add_argument("--doctor-model", default="", help="Optional model override for Doctor backend")
    args = parser.parse_args()

    sot_path = Path(args.sot_path)
    index_path = Path(args.index_path)
    if not sot_path.exists():
        raise SystemExit(f"Missing SoT file: {sot_path}")
    if not index_path.exists():
        raise SystemExit(f"Missing index file: {index_path}")

    sot = _load_json(sot_path)
    index = _load_json(index_path)
    matches = retrieve_similar_experiments(query_text=args.query, sot=sot, vector_index=index, top_k=args.top_k)
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

    print("=== Retrieval v1 Result ===")
    if matches:
        top = matches[0]
        print(
            f"top_match={top.experiment_id} similarity={top.score} "
            f"primary_metric={top.primary_metric_outcome.get('metric_id')} "
            f"guardrail_breach={top.guardrail_breach.get('metric_id')}"
        )
    else:
        print("top_match=none")
    print(f"doctor_backend={args.doctor_backend}")
    print("")
    print(card)
    print(f"\nSaved Decision Card: {out_card}")


if __name__ == "__main__":
    _run_cli()
