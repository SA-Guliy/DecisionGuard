from __future__ import annotations

from pathlib import Path


def llm_reports_dir() -> Path:
    return Path("data/llm_reports")


def agent_reports_dir() -> Path:
    return Path("data/agent_reports")


def ab_preflight_dir() -> Path:
    return Path("data/ab_preflight")


def diagnostics_dir() -> Path:
    return Path("data/diagnostics")


def logs_dir() -> Path:
    return Path("data/logs")


def security_reports_dir() -> Path:
    return Path("data/security_reports")


def security_report_json(run_id: str) -> Path:
    return security_reports_dir() / f"security_{run_id}.json"


def run_all_log_path(run_id: str) -> Path:
    return logs_dir() / f"run_all_{run_id}.log"


def ops_report_dir(run_id: str) -> Path:
    return Path("reports/L1_ops") / str(run_id)


def captain_report_json(run_id: str) -> Path:
    return llm_reports_dir() / f"{run_id}_captain.json"


def doctor_report_json(run_id: str) -> Path:
    return agent_reports_dir() / f"{run_id}_doctor_variance.json"


def evaluator_report_json(run_id: str) -> Path:
    return agent_reports_dir() / f"{run_id}_experiment_evaluator.json"


def commander_report_json(run_id: str) -> Path:
    return agent_reports_dir() / f"{run_id}_commander_priority.json"


def narrative_report_json(run_id: str) -> Path:
    return agent_reports_dir() / f"{run_id}_narrative_analyst.json"


def ab_preflight_json(run_id: str, experiment_id: str) -> Path:
    return ab_preflight_dir() / f"{run_id}_{experiment_id}_preflight.json"


def cohort_evidence_pack_json(run_id: str) -> Path:
    return ops_report_dir(run_id) / "cohort_evidence_pack.json"


def agent_reasoning_trace_md(run_id: str) -> Path:
    return ops_report_dir(run_id) / "AGENT_REASONING_TRACE.md"


def agent_interaction_friction_registry_json() -> Path:
    return diagnostics_dir() / "agent_interaction_friction_registry.json"


def agent_interaction_friction_report_md() -> Path:
    return Path("reports/L1_ops/AGENT_INTERACTION_FRICTION_REPORT.md")
