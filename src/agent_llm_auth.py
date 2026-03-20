from __future__ import annotations

from typing import Any

from src.artifact_loaders import load_core_agent_artifacts


def safe_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def looks_real_llm_model(model_name: Any) -> bool:
    m = str(model_name or "").strip().lower()
    return bool(m) and m not in {"missing", "local_mock", "none", "local_backend"}


def truthy_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes"}
    return bool(v)


def doctor_methodology_obj(doctor: dict[str, Any]) -> dict[str, Any]:
    method = safe_dict(doctor.get("ab_interpretation_methodology"))
    if method:
        return method
    return safe_dict(doctor.get("statistical_methodology_summary"))


def doctor_methodology_provenance(doctor: dict[str, Any]) -> dict[str, Any]:
    llm_prov = safe_dict(doctor.get("llm_provenance"))
    top = safe_dict(llm_prov.get("methodology_selection"))
    if top:
        return top
    method = doctor_methodology_obj(doctor)
    prov = safe_dict(method.get("selection_provenance"))
    if prov:
        return prov
    out: dict[str, Any] = {}
    if method.get("selected_by") is not None:
        out["selected_by"] = method.get("selected_by")
    if method.get("fallback_reason") is not None:
        out["fallback_reason"] = method.get("fallback_reason")
    return out


def doctor_method_selected_by_and_model(doctor: dict[str, Any]) -> tuple[str, str]:
    method = doctor_methodology_obj(doctor)
    prov = doctor_methodology_provenance(doctor)
    selected_by = str(prov.get("selected_by") or method.get("selected_by") or "missing")
    model_intent = str(prov.get("model_intent") or doctor.get("model_used") or "missing")
    return selected_by, model_intent


def doctor_summary_local_mock_detected(doctor: dict[str, Any]) -> bool:
    prov = safe_dict(safe_dict(doctor.get("llm_provenance")).get("human_summary"))
    if str(prov.get("model", "")).strip().lower() == "local_mock":
        return True
    text = str(doctor.get("human_summary_md", "") or "").lower()
    return "local_mock" in text or "llm disabled" in text


def captain_llm_auth(captain: dict[str, Any]) -> dict[str, Any]:
    model = str(captain.get("model", "missing") or "missing")
    prov = safe_dict(captain.get("llm_provenance"))
    fallback = bool(captain.get("fallback_used", False)) or model == "local_mock"
    selected_before_fallback = str(prov.get("selected_model_before_fallback") or model or "missing")
    llm_path_reached = (
        looks_real_llm_model(selected_before_fallback)
        or (truthy_bool(prov.get("attempted_llm_path")) and str(prov.get("fallback_reason", "")).strip() != "local_mock_backend")
        or (
            truthy_bool(prov.get("remote_allowed"))
            and str(prov.get("fallback_reason", "")).strip() in {"llm_parse_failed", "llm_runtime_error"}
        )
    )
    real_llm = looks_real_llm_model(model) and not fallback
    return {
        "model": model,
        "provenance": prov,
        "fallback": fallback,
        "selected_model_before_fallback": selected_before_fallback,
        "llm_path_reached": llm_path_reached,
        "real_llm": real_llm,
    }


def doctor_llm_auth(doctor: dict[str, Any]) -> dict[str, Any]:
    model_used = str(doctor.get("model_used", "missing") or "missing")
    method = doctor_methodology_obj(doctor)
    method_prov = doctor_methodology_provenance(doctor)
    method_selected_by = str(method_prov.get("selected_by") or method.get("selected_by") or "missing")
    method_model = str(method_prov.get("model_intent") or model_used or "missing")
    fallback_reason = str(method_prov.get("fallback_reason") or method.get("fallback_reason") or "")
    remote_allowed = method_prov.get("remote_allowed")
    real_llm = (method_selected_by == "doctor_llm_validated") and looks_real_llm_model(method_model)
    llm_path_reached = False
    if real_llm:
        llm_path_reached = True
    elif truthy_bool(method_prov.get("remote_allowed")) and str(method_prov.get("backend_requested", "")).strip().lower() in {"groq", "auto"}:
        if looks_real_llm_model(method_prov.get("actual_model") or method_prov.get("model_intent") or method_model):
            llm_path_reached = True
        elif fallback_reason.startswith("llm_methodology_"):
            llm_path_reached = True
    return {
        "model_used": model_used,
        "method": method,
        "method_provenance": method_prov,
        "method_selected_by": method_selected_by,
        "method_model": method_model,
        "method_fallback_reason": fallback_reason,
        "method_remote_allowed": remote_allowed,
        "human_summary_local_mock": doctor_summary_local_mock_detected(doctor),
        "llm_path_reached": llm_path_reached,
        "real_llm": real_llm,
    }


def commander_llm_auth(commander: dict[str, Any]) -> dict[str, Any]:
    cmd_model = str(commander.get("commander_model", "missing") or "missing")
    prov = safe_dict(commander.get("llm_decision_provenance"))
    model = str(prov.get("model") or cmd_model or "missing")
    fallback = bool(prov.get("used_fallback", False)) or model == "local_mock"
    real_llm = looks_real_llm_model(model) and not fallback
    llm_path_reached = False
    if real_llm:
        llm_path_reached = True
    elif truthy_bool(prov.get("remote_allowed")) and str(prov.get("backend_requested", "")).strip().lower() in {"groq", "auto"}:
        if looks_real_llm_model(model):
            llm_path_reached = True
        elif str(prov.get("fallback_reason", "")).strip().startswith("llm_"):
            llm_path_reached = True
    return {
        "commander_model": cmd_model,
        "model": model,
        "provenance": prov,
        "fallback": fallback,
        "llm_path_reached": llm_path_reached,
        "real_llm": real_llm,
    }


def core_agent_llm_authenticity_from_artifacts(
    run_id: str,
    captain: dict[str, Any],
    doctor: dict[str, Any],
    commander: dict[str, Any],
) -> dict[str, Any]:
    cap = captain_llm_auth(captain)
    doc = doctor_llm_auth(doctor)
    cmd = commander_llm_auth(commander)

    return {
        "run_id": run_id,
        "captain": {
            "real_llm": cap["real_llm"],
            "llm_path_reached": cap["llm_path_reached"],
            "model": cap["model"],
            "selected_model_before_fallback": cap["selected_model_before_fallback"],
            "fallback": cap["fallback"],
        },
        "doctor": {
            "real_llm": doc["real_llm"],
            "llm_path_reached": doc["llm_path_reached"],
            "method_selected_by": doc["method_selected_by"],
            "method_model": doc["method_model"],
            "fallback_reason": doc["method_fallback_reason"],
        },
        "commander": {
            "real_llm": cmd["real_llm"],
            "llm_path_reached": cmd["llm_path_reached"],
            "model": cmd["model"],
            "remote_allowed": cmd["provenance"].get("remote_allowed"),
            "fallback": cmd["fallback"],
            "fallback_reason": cmd["provenance"].get("fallback_reason"),
        },
        "llm_path_reached_agents_count": int(cap["llm_path_reached"]) + int(doc["llm_path_reached"]) + int(cmd["llm_path_reached"]),
        "real_llm_agents_count": int(cap["real_llm"]) + int(doc["real_llm"]) + int(cmd["real_llm"]),
    }


def core_agent_llm_authenticity(run_id: str) -> dict[str, Any]:
    arts = load_core_agent_artifacts(run_id)
    return core_agent_llm_authenticity_from_artifacts(run_id, arts["captain"], arts["doctor"], arts["commander"])
