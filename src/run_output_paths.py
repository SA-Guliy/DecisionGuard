from __future__ import annotations

from pathlib import Path
from typing import Iterable

from src.paths import (
    commander_report_json,
    doctor_report_json,
    evaluator_report_json,
    ops_report_dir,
)


def dq_report_json(run_id: str) -> Path:
    return Path("data/dq_reports") / f"{run_id}.json"


def captain_report_md(run_id: str) -> Path:
    return Path("data/llm_reports") / f"{run_id}_captain.md"


def metrics_snapshot_json(run_id: str) -> Path:
    return Path("data/metrics_snapshots") / f"{run_id}.json"


def synthetic_bias_report_json(run_id: str) -> Path:
    return Path("data/realism_reports") / f"{run_id}_synthetic_bias.json"


def approvals_registry_json(run_id: str) -> Path:
    return Path("data/governance") / f"approvals_{run_id}.json"


def action_trace_jsonl(run_id: str) -> Path:
    return Path("data/decision_traces") / f"{run_id}_actions.jsonl"


def agent_governance_json(run_id: str) -> Path:
    return Path("data/agent_governance") / f"{run_id}_agent_approvals.json"


def adversarial_suite_json(run_id: str) -> Path:
    return Path("data/eval") / f"adversarial_suite_{run_id}.json"


def agent_effectiveness_report_json(run_id: str) -> Path:
    return Path("data/agent_reports") / f"{run_id}_agent_effectiveness.json"


def agent_value_eval_json(run_id: str) -> Path:
    return Path("data/agent_eval") / f"{run_id}_agent_value_eval.json"


def agent_quality_v2_json(run_id: str) -> Path:
    return Path("data/agent_quality") / f"{run_id}_agent_quality_v2.json"


def pre_publish_audit_json(run_id: str) -> Path:
    return Path("data/agent_quality") / f"{run_id}_pre_publish_audit.json"


def ab_report_json(run_id: str, experiment_id: str) -> Path:
    return Path("data/ab_reports") / f"{run_id}_{experiment_id}_ab.json"


def l1_decision_card_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "decision_card.md"


def l1_index_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "index.md"


def l1_goal_scorecard_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "goal_scorecard.md"


def l1_synthetic_realism_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "synthetic_realism.md"


def l1_agent_quality_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "agent_quality.md"


def l1_agent_governance_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "agent_governance.md"


def l1_agent_scorecard_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "AGENT_SCORECARD.md"


def l1_contract_check_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "contract_check.md"


def l1_agent_scoreboard_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "AGENT_SCOREBOARD.md"


def l1_agent_value_scorecard_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "AGENT_VALUE_SCORECARD.md"


def l1_demo_index_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "DEMO_INDEX.md"


def human_hub_index_md(run_id: str) -> Path:
    return Path("human_reports/L1") / str(run_id) / "index.md"


def run_completion_summary_paths(run_id: str, experiment_id: str = "") -> list[tuple[str, Path]]:
    exp = str(experiment_id or "").strip()
    rows: list[tuple[str, Path]] = [
        ("dq_report", dq_report_json(run_id)),
        ("captain_md", captain_report_md(run_id)),
        ("metrics_snapshot", metrics_snapshot_json(run_id)),
        ("doctor_variance_report", doctor_report_json(run_id)),
        ("experiment_evaluator_report", evaluator_report_json(run_id)),
        ("commander_report", commander_report_json(run_id)),
        ("synthetic_bias_report", synthetic_bias_report_json(run_id)),
    ]
    if exp:
        rows.append(("ab_report", ab_report_json(run_id, exp)))
    rows.extend(
        [
            ("l1_index", l1_index_md(run_id)),
            ("l1_decision_card", l1_decision_card_md(run_id)),
            ("l1_goal_scorecard", l1_goal_scorecard_md(run_id)),
            ("l1_agent_scoreboard", l1_agent_scoreboard_md(run_id)),
            ("l1_agent_scorecard_v2", l1_agent_scorecard_md(run_id)),
            ("l1_agent_value_scorecard", l1_agent_value_scorecard_md(run_id)),
            ("l1_demo_index", l1_demo_index_md(run_id)),
            ("human_hub_index", human_hub_index_md(run_id)),
            ("l1_realism_report", l1_synthetic_realism_md(run_id)),
            ("l1_agent_quality_report", l1_agent_quality_md(run_id)),
            ("l1_agent_governance_report", l1_agent_governance_md(run_id)),
            ("approvals_registry", approvals_registry_json(run_id)),
            ("action_trace", action_trace_jsonl(run_id)),
            ("agent_governance", agent_governance_json(run_id)),
            ("adversarial_suite", adversarial_suite_json(run_id)),
            ("agent_effectiveness_report", agent_effectiveness_report_json(run_id)),
            ("agent_value_eval_report", agent_value_eval_json(run_id)),
            ("agent_quality_v2_report", agent_quality_v2_json(run_id)),
            ("l1_contract_check_report", l1_contract_check_md(run_id)),
            ("pre_publish_audit", pre_publish_audit_json(run_id)),
        ]
    )
    return rows


def iter_run_completion_summary_paths(run_id: str, experiment_id: str = "") -> Iterable[tuple[str, Path]]:
    return run_completion_summary_paths(run_id, experiment_id)
