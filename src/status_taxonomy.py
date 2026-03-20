from __future__ import annotations

from typing import Any

from src.domain_template import ConfigurationError, domain_goal_metric_sets


def _goal_sets() -> dict[str, set[str]]:
    sets = domain_goal_metric_sets()
    if not sets:
        raise ConfigurationError("Missing Domain Template goal metric sets")
    return sets

MEASUREMENT_BLOCKED_STATES = frozenset({"UNOBSERVABLE", "BLOCKED_BY_DATA"})

AB_DECISION_INVALID_STATUSES = frozenset(
    {
        "MISSING_ASSIGNMENT",
        "METHODOLOGY_MISMATCH",
        "INVALID_METHODS",
        "ASSIGNMENT_RECOVERED",
    }
)

AB_METHOD_VALIDITY_ERROR_STATUSES = frozenset({"INVALID_METHODS", "METHODOLOGY_MISMATCH"})


def normalize_status(value: Any) -> str:
    return str(value or "").strip().upper()


def goal_from_metric(metric: str | None) -> str:
    m = str(metric or "").strip().lower()
    sets = _goal_sets()
    for goal_id, metrics in sets.items():
        if m in metrics:
            return str(goal_id)
    return "unknown"


def is_measurement_blocked(state: Any) -> bool:
    return normalize_status(state) in MEASUREMENT_BLOCKED_STATES


def is_ab_decision_invalid(status: Any) -> bool:
    return normalize_status(status) in AB_DECISION_INVALID_STATUSES


def is_ab_method_validity_error(status: Any) -> bool:
    return normalize_status(status) in AB_METHOD_VALIDITY_ERROR_STATUSES
