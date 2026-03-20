#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.security_profile import load_security_profile
from src.architecture_v3 import (
    SANITIZATION_POLICY_PATH,
    SANITIZATION_TRANSFORM_PATH,
    GATE_SEQUENCE,
    anti_goodhart_verdict_path,
    governance_ceiling_path,
    list_gate_results,
    load_gate_result,
    load_json_with_integrity,
)
from src.security_utils import verify_json_manifest, verify_manifest_scope, verify_sha256_sidecar
from src.sanitization_transform import verify_encrypted_map_document

SCAN_TARGETS = [
    "README.md",
    "docs",
    "domain_templates",
    "configs",
    "src",
    "reports",
    "archive",
    "data/archive",
    "data/logs",
    "data/agent_reports",
    "scripts",
]
_RUNTIME_SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")
_FORBIDDEN_RUNTIME_CLOUD_PATTERNS = (
    re.compile(r"^\s*from\s+src\.llm_client\s+import\s+get_llm_backend", re.MULTILINE),
    re.compile(r"(^|[^\"'])_client\.chat\.completions\.create\(", re.MULTILINE),
    re.compile(r"(^|[^\"'])api\.openai\.com", re.MULTILINE),
)
ARTIFACT_SPAM_POLICY_PATH = Path("configs/contracts/artifact_spam_prevention_v2.json")
GOLDEN_PAIR_POLICY_PATH = Path("configs/contracts/golden_pair_policy_v2.json")
CLEANUP_INTEGRITY_POLICY_PATH = Path("configs/contracts/cleanup_integrity_policy_v2.json")
BATCH_TRANSPORT_POLICY_PATH = Path("configs/contracts/batch_record_transport_policy_v2.json")


def _is_run_scoped_finding(finding: dict[str, Any], run_id: str) -> bool:
    rid = str(run_id or "").strip()
    if not rid:
        return True
    for key in ("path", "detail", "label"):
        value = str(finding.get(key, "") or "")
        if rid and rid in value:
            return True
    return False

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("dsn", re.compile(r"postgresql://\S+", re.IGNORECASE)),
    ("api_key", re.compile(r"[A-Za-z0-9_]*_API_KEY\s*=\s*\S+", re.IGNORECASE)),
    ("password", re.compile(r"password\s*=\s*\S+", re.IGNORECASE)),
    ("token", re.compile(r"token\s*=\s*\S+", re.IGNORECASE)),
    ("json_secret_kv", re.compile(r"[\"'](?:token|password|api[_-]?key|secret)[\"']\s*:\s*[\"'][^\"']+[\"']", re.IGNORECASE)),
    ("yaml_secret_kv", re.compile(r"^\s*(token|password|api[_-]?key|secret)\s*:\s*\S+", re.IGNORECASE)),
    ("bearer_token", re.compile(r"\bbearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE)),
    ("groq_key", re.compile(r"gsk_[A-Za-z0-9_\-]+")),
]

ABS_PATH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("absolute_unix_path", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("absolute_windows_path", re.compile(r"[A-Za-z]:\\\\")),
]


def _iter_files() -> list[Path]:
    out: list[Path] = []
    for target in SCAN_TARGETS:
        p = Path(target)
        if not p.exists():
            continue
        if p.is_file():
            out.append(p)
            continue
        for child in p.rglob("*"):
            if child.is_file():
                out.append(child)
    return out


def _runtime_scope_scripts_from_run_all() -> list[Path]:
    run_all_path = Path("scripts/run_all.py")
    if not run_all_path.exists():
        return []
    try:
        text = run_all_path.read_text(encoding="utf-8")
    except Exception:
        return []
    out: list[Path] = []
    seen: set[str] = set()
    for rel in sorted(set(_RUNTIME_SCRIPT_RE.findall(text))):
        if rel.startswith("scripts/admin_"):
            continue
        if rel in seen:
            continue
        p = Path(rel)
        if p.exists() and p.is_file():
            out.append(p)
            seen.add(rel)
    return out


def _scan_text_file(path: Path, run_id: str = "") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        # Avoid flagging regex definitions in source code as leaked secrets.
        if "re.compile(" in line:
            continue
        for typ, pattern in SECRET_PATTERNS + ABS_PATH_PATTERNS:
            if pattern.search(line):
                if typ == "dsn" and "postgresql:///?service=" in line:
                    # Service aliases are expected in code/config and do not expose credentials.
                    continue
                severity = "ERROR" if typ in {
                    "dsn",
                    "api_key",
                    "password",
                    "token",
                    "groq_key",
                    "json_secret_kv",
                    "yaml_secret_kv",
                    "bearer_token",
                } else "WARN"
                # service-based DSN (postgresql:///?service=...) has no embedded secret; keep as warning.
                if typ == "dsn" and "postgresql:///?service=" in line:
                    severity = "WARN"
                # Historical logs often contain local absolute paths; audit the current run strictly.
                if (
                    typ == "absolute_unix_path"
                    and str(path).startswith("data/logs/")
                    and run_id
                    and run_id not in path.name
                ):
                    continue
                findings.append({
                    "type": typ,
                    "path": str(path),
                    "line": lineno,
                    "severity": severity,
                })
    return findings


def _load_contract_with_integrity(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        return None, f"missing_contract:{path}"
    ok, reason = verify_sha256_sidecar(path, required=True)
    if not ok:
        return None, reason
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"invalid_contract_json:{path}:{exc}"
    if not isinstance(payload, dict):
        return None, f"invalid_contract_payload:{path}"
    return payload, ""


def _match_any(path: Path, globs: list[str]) -> bool:
    norm = str(path).replace("\\", "/")
    return any(fnmatch.fnmatch(norm, g.replace("\\", "/")) for g in globs if str(g).strip())


def _scan_links(run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not run_id:
        return findings
    links_path = Path(f"reports/L1_ops/{run_id}/links.json")
    if not links_path.exists():
        return [{"type": "missing_links", "path": str(links_path), "line": 0, "severity": "WARN"}]
    try:
        links = json.loads(links_path.read_text(encoding="utf-8"))
    except Exception:
        return [{"type": "invalid_links_json", "path": str(links_path), "line": 0, "severity": "WARN"}]

    def _check_path(raw: Any, label: str) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        p = Path(raw)
        if not p.exists():
            findings.append({"type": "missing_artifact", "path": raw, "line": 0, "severity": "WARN", "label": label})

    inputs = links.get("inputs", {}) if isinstance(links.get("inputs"), dict) else {}
    outputs = links.get("outputs", {}) if isinstance(links.get("outputs"), dict) else {}
    for k, v in inputs.items():
        _check_path(v, f"inputs.{k}")
    for k, v in outputs.items():
        if isinstance(v, list):
            for i, item in enumerate(v):
                _check_path(item, f"outputs.{k}[{i}]")
        else:
            _check_path(v, f"outputs.{k}")
    return findings


def _scan_json_integrity_manifest(
    run_id: str,
    *,
    strict_manifest_scope: bool,
    manifest_scope_ignore_globs: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not run_id:
        return findings
    out_dir = Path(f"reports/L1_ops/{run_id}")
    links_path = out_dir / "links.json"
    manifest_path = out_dir / "artifact_manifest.json"

    links_ok, links_reason = verify_sha256_sidecar(links_path, required=True)
    if not links_ok:
        findings.append(
            {
                "type": "links_integrity_error",
                "path": str(links_path),
                "line": 0,
                "severity": "ERROR",
                "detail": links_reason,
            }
        )

    manifest_ok, manifest_issues = verify_json_manifest(
        manifest_path,
        require_manifest=True,
        verify_manifest_sidecar=True,
    )
    if not manifest_ok:
        for issue in manifest_issues[:20]:
            findings.append(
                {
                    "type": "json_manifest_integrity_error",
                    "path": str(manifest_path),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": issue,
                }
            )
    if strict_manifest_scope:
        scope_ok, scope_issues = verify_manifest_scope(
            manifest_path,
            run_id=run_id,
            ignore_globs=manifest_scope_ignore_globs,
            require_manifest=True,
        )
        if not scope_ok:
            for issue in scope_issues[:20]:
                findings.append(
                    {
                        "type": "json_manifest_scope_error",
                        "path": str(manifest_path),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": issue,
                    }
                )
    return findings


def _scan_poc_artifact_spam_policy() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    spam_contract, spam_err = _load_contract_with_integrity(ARTIFACT_SPAM_POLICY_PATH)
    golden_contract, golden_err = _load_contract_with_integrity(GOLDEN_PAIR_POLICY_PATH)
    cleanup_contract, cleanup_err = _load_contract_with_integrity(CLEANUP_INTEGRITY_POLICY_PATH)
    transport_contract, transport_err = _load_contract_with_integrity(BATCH_TRANSPORT_POLICY_PATH)
    for path, err, label in (
        (ARTIFACT_SPAM_POLICY_PATH, spam_err, "artifact_spam_prevention_contract_invalid"),
        (GOLDEN_PAIR_POLICY_PATH, golden_err, "golden_pair_policy_contract_invalid"),
        (CLEANUP_INTEGRITY_POLICY_PATH, cleanup_err, "cleanup_integrity_policy_contract_invalid"),
        (BATCH_TRANSPORT_POLICY_PATH, transport_err, "batch_record_transport_policy_contract_invalid"),
    ):
        if err:
            findings.append(
                {
                    "type": label,
                    "path": str(path),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": err,
                }
            )

    spam_policy = spam_contract.get("policy") if isinstance(spam_contract, dict) and isinstance(spam_contract.get("policy"), dict) else {}
    golden_policy = golden_contract.get("policy") if isinstance(golden_contract, dict) and isinstance(golden_contract.get("policy"), dict) else {}
    cleanup_policy = cleanup_contract.get("policy") if isinstance(cleanup_contract, dict) and isinstance(cleanup_contract.get("policy"), dict) else {}
    transport_policy = transport_contract.get("policy") if isinstance(transport_contract, dict) and isinstance(transport_contract.get("policy"), dict) else {}

    forbidden_globs = [str(x) for x in spam_policy.get("forbidden_globs", []) if str(x).strip()]
    excluded_globs = [str(x) for x in spam_policy.get("excluded_globs", []) if str(x).strip()]
    golden_card_glob = str(golden_policy.get("allowed_card_glob", "")).strip()
    golden_json_glob = str(golden_policy.get("allowed_json_glob", "")).strip()
    if golden_card_glob:
        excluded_globs.append(golden_card_glob)
    if golden_json_glob:
        excluded_globs.append(golden_json_glob)
        excluded_globs.append(f"{golden_json_glob}.sha256")

    for pattern in forbidden_globs:
        for p in Path().glob(pattern):
            if not p.is_file():
                continue
            rel = Path(str(p).replace("\\", "/"))
            if str(rel).startswith("_PROJECT_TRASH/"):
                continue
            if _match_any(rel, excluded_globs):
                continue
            findings.append(
                {
                    "type": "poc_artifact_spam_detected",
                    "path": str(rel),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": f"forbidden_pattern={pattern}",
                }
            )

    strict_integrity = bool(cleanup_policy.get("strict_integrity_default", True))
    if strict_integrity:
        golden_targets: list[Path] = []
        if golden_card_glob:
            golden_targets.extend([p for p in Path().glob(golden_card_glob) if p.is_file()])
        if golden_json_glob:
            golden_targets.extend([p for p in Path().glob(golden_json_glob) if p.is_file()])
        for gp in golden_targets:
            ok_gp, reason_gp = verify_sha256_sidecar(gp, required=True)
            if not ok_gp:
                findings.append(
                    {
                        "type": "poc_golden_pair_integrity_invalid",
                        "path": str(gp),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": reason_gp,
                    }
                )

    if str(transport_policy.get("summary_source_only", "")).strip() != "data/batch_eval/<batch_id>_summary.json":
        findings.append(
            {
                "type": "consolidated_summary_only_policy_invalid",
                "path": str(BATCH_TRANSPORT_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": "summary_source_only must be data/batch_eval/<batch_id>_summary.json",
            }
        )
    consolidated = Path("scripts/build_batch_consolidated_report.py")
    if consolidated.exists():
        try:
            text = consolidated.read_text(encoding="utf-8")
        except Exception:
            text = ""
            findings.append(
                {
                    "type": "consolidated_summary_only_policy_invalid",
                    "path": str(consolidated),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "unreadable script",
                }
            )
        for marker in (
            "_PROJECT_TRASH/data/agent_reports",
            "data/agent_reports/{run_id}_poc_sprint2.json",
            "_load_agent_report_fallback(",
            "data/batch_eval/staging",
        ):
            if marker in text:
                findings.append(
                    {
                        "type": "consolidated_summary_only_policy_invalid",
                        "path": str(consolidated),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": f"forbidden_dependency={marker}",
                    }
                )
    return findings


def _scan_run_all_script_refs() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    run_all = Path("scripts/run_all.py")
    if not run_all.exists():
        return [{"type": "missing_run_all", "path": str(run_all), "line": 0, "severity": "ERROR"}]
    try:
        text = run_all.read_text(encoding="utf-8")
    except Exception:
        return [{"type": "invalid_run_all", "path": str(run_all), "line": 0, "severity": "ERROR"}]
    for m in re.finditer(r"\"scripts/([A-Za-z0-9_]+\\.py)\"", text):
        rel = f"scripts/{m.group(1)}"
        if not Path(rel).exists():
            findings.append(
                {
                    "type": "missing_script_ref",
                    "path": rel,
                    "line": text[: m.start()].count("\\n") + 1,
                    "severity": "ERROR",
                }
            )
    return findings


def _scan_assignment_recovery_governance(run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not run_id:
        return findings

    ab_paths = sorted(Path("data/ab_reports").glob(f"{run_id}_*_ab.json"))
    if not ab_paths:
        return findings

    commander_path = Path(f"data/agent_reports/{run_id}_commander_priority.json")
    evaluator_path = Path(f"data/agent_reports/{run_id}_experiment_evaluator.json")
    commander = {}
    evaluator = {}
    try:
        commander = json.loads(commander_path.read_text(encoding="utf-8")) if commander_path.exists() else {}
    except Exception:
        commander = {}
    try:
        evaluator = json.loads(evaluator_path.read_text(encoding="utf-8")) if evaluator_path.exists() else {}
    except Exception:
        evaluator = {}

    commander_decision = str(commander.get("normalized_decision", commander.get("decision", ""))).upper().strip()
    evaluator_decision = str(evaluator.get("decision", "")).upper().strip()
    blocked_set = {"GO", "RUN_AB", "ROLLOUT", "ROLLOUT_CANDIDATE"}

    for ab_path in ab_paths:
        try:
            ab = json.loads(ab_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        ab_status = str(ab.get("status", "")).upper().strip()
        if ab_status != "ASSIGNMENT_RECOVERED":
            continue
        if commander_decision in blocked_set:
            findings.append(
                {
                    "type": "governance_assignment_recovered_violation",
                    "path": str(ab_path),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": (
                        f"ab_status={ab_status} but commander_decision={commander_decision}; "
                        "post-hoc reconstructed assignment must never be GO/RUN_AB/ROLLOUT"
                    ),
                }
            )
        if evaluator_decision in blocked_set:
            findings.append(
                {
                    "type": "governance_assignment_recovered_violation",
                    "path": str(ab_path),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": (
                        f"ab_status={ab_status} but evaluator_decision={evaluator_decision}; "
                        "post-hoc reconstructed assignment must never be GO/RUN_AB/ROLLOUT"
                    ),
                }
            )
    return findings


def _scan_v3_runtime_contracts(run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not run_id:
        return findings

    verdict = None
    verdict_err = ""
    try:
        verdict = load_json_with_integrity(anti_goodhart_verdict_path(run_id))
    except Exception as exc:
        verdict_err = str(exc)
    if not isinstance(verdict, dict) or str(verdict.get("status", "")).upper() != "PASS":
        findings.append(
            {
                "type": "anti_goodhart_sot_invalid",
                "path": str(anti_goodhart_verdict_path(run_id)),
                "line": 0,
                "severity": "ERROR",
                "detail": verdict_err or (verdict if isinstance(verdict, dict) else "missing"),
            }
        )

    gates: dict[str, dict[str, Any]] = {}
    for p in list_gate_results(run_id):
        try:
            row = load_gate_result(p)
        except Exception as exc:
            findings.append(
                {
                    "type": "gate_result_invalid",
                    "path": str(p),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": str(exc),
                }
            )
            continue
        gate_name = str(row.get("gate_name", "")).strip()
        if gate_name:
            gates[gate_name] = row

    required = [g for g in GATE_SEQUENCE if g != "pre_publish"]
    if "captain" not in required:
        required = ["captain", *required]
    for gate in required:
        row = gates.get(gate)
        if not isinstance(row, dict):
            findings.append(
                {
                    "type": "gate_result_missing",
                    "path": f"data/gates/{run_id}_{gate}_gate_result.json",
                    "line": 0,
                    "severity": "ERROR",
                }
            )
            continue
        if str(row.get("status", "")).upper() != "PASS":
            findings.append(
                {
                    "type": "gate_result_failed",
                    "path": f"data/gates/{run_id}_{gate}_gate_result.json",
                    "line": 0,
                    "severity": "ERROR",
                    "detail": row.get("error_code"),
                }
            )

    gov = None
    gov_err = ""
    try:
        gov = load_json_with_integrity(governance_ceiling_path(run_id))
    except Exception as exc:
        gov_err = str(exc)
    if not isinstance(gov, dict):
        findings.append(
            {
                "type": "governance_ceiling_missing",
                "path": str(governance_ceiling_path(run_id)),
                "line": 0,
                "severity": "ERROR",
                "detail": gov_err,
            }
        )
    else:
        if str(gov.get("governance_status", "")).strip().lower() == "missing_review":
            required_actions = gov.get("required_actions", []) if isinstance(gov.get("required_actions"), list) else []
            if not required_actions:
                findings.append(
                    {
                        "type": "governance_required_actions_missing",
                        "path": str(governance_ceiling_path(run_id)),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": "governance_status=missing_review requires non-empty required_actions",
                    }
                )

    return findings


def _scan_cloud_gateway_policy() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in _runtime_scope_scripts_from_run_all():
        if not path.exists():
            findings.append({"type": "llm_gateway_policy_violation", "path": str(path), "line": 0, "severity": "ERROR", "detail": "missing_script"})
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            findings.append({"type": "llm_gateway_policy_violation", "path": str(path), "line": 0, "severity": "ERROR", "detail": "unreadable_script"})
            continue
        for pat in _FORBIDDEN_RUNTIME_CLOUD_PATTERNS:
            if pat.search(text):
                findings.append(
                    {
                        "type": "llm_gateway_policy_violation",
                        "path": str(path),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": pat.pattern,
                    }
                )
    return findings


def _scan_sanitization_map_policy(run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        policy = load_json_with_integrity(SANITIZATION_POLICY_PATH)
    except Exception as exc:
        return [
            {
                "type": "sanitization_policy_contract_invalid",
                "path": str(SANITIZATION_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": str(exc),
            }
        ]
    try:
        transform_contract = load_json_with_integrity(SANITIZATION_TRANSFORM_PATH)
    except Exception as exc:
        findings.append(
            {
                "type": "sanitization_transform_contract_invalid",
                "path": str(SANITIZATION_TRANSFORM_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": str(exc),
            }
        )
        transform_contract = None

    if str(policy.get("storage_policy", "")).strip() != "security_obfuscation_map_only":
        findings.append(
            {
                "type": "sanitization_policy_contract_invalid",
                "path": str(SANITIZATION_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": "storage_policy must be security_obfuscation_map_only",
            }
        )
    if str(policy.get("encryption_algorithm", "")).strip() != "openssl_aes_256_cbc_pbkdf2":
        findings.append(
            {
                "type": "sanitization_policy_contract_invalid",
                "path": str(SANITIZATION_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": "encryption_algorithm must be openssl_aes_256_cbc_pbkdf2",
            }
        )
    if bool(policy.get("kms_envelope_required", False)) is not True:
        findings.append(
            {
                "type": "sanitization_policy_contract_invalid",
                "path": str(SANITIZATION_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": "kms_envelope_required must be true",
            }
        )
    if bool(policy.get("decrypt_roundtrip_required", False)) is not True:
        findings.append(
            {
                "type": "sanitization_policy_contract_invalid",
                "path": str(SANITIZATION_POLICY_PATH),
                "line": 0,
                "severity": "ERROR",
                "detail": "decrypt_roundtrip_required must be true",
            }
        )
    if isinstance(transform_contract, dict):
        if str(transform_contract.get("transform_mode", "")).strip() != "vectorized_placeholder_map":
            findings.append(
                {
                    "type": "sanitization_transform_contract_invalid",
                    "path": str(SANITIZATION_TRANSFORM_PATH),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "transform_mode must be vectorized_placeholder_map",
                }
            )
        if bool(transform_contract.get("response_deobfuscation_required", False)) is not True:
            findings.append(
                {
                    "type": "sanitization_transform_contract_invalid",
                    "path": str(SANITIZATION_TRANSFORM_PATH),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "response_deobfuscation_required must be true",
                }
            )

    forbidden_roots = [Path("reports"), Path("human_reports"), Path("data/agent_reports")]
    for root in forbidden_roots:
        if not root.exists():
            continue
        for p in root.rglob("*obfusc*map*.json"):
            if not p.is_file():
                continue
            findings.append(
                {
                    "type": "sanitization_map_forbidden_publication",
                    "path": str(p),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "obfuscation map must be kept only under data/security/obfuscation_maps",
                }
            )

    map_root = Path("data/security/obfuscation_maps")
    map_files = sorted([p for p in map_root.glob("*.json") if p.is_file() and p.name != "audit_log.jsonl" and not p.name.endswith("_manifest.json")])
    for map_file in map_files:
        ok_sidecar, sidecar_reason = verify_sha256_sidecar(map_file, required=True)
        if not ok_sidecar:
            findings.append(
                {
                    "type": "sanitization_map_integrity_invalid",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": sidecar_reason,
                }
            )
            continue
        try:
            payload = load_json_with_integrity(map_file)
        except Exception as exc:
            findings.append(
                {
                    "type": "sanitization_map_integrity_invalid",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": str(exc),
                }
            )
            continue
        enc_ok, enc_reason = verify_encrypted_map_document(
            payload,
            kms_key_ref=str(policy.get("kms_key_ref", "")),
            require_roundtrip=bool(policy.get("decrypt_roundtrip_required", True)),
        )
        if not enc_ok:
            findings.append(
                {
                    "type": "map_encryption_verified",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": enc_reason,
                }
            )
        if bool(payload.get("sanitization_vectorization_applied", False)) is not True:
            findings.append(
                {
                    "type": "sanitization_vectorization_applied",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "sanitization_vectorization_applied=false",
                }
            )
        if bool(payload.get("response_deobfuscation_required", False)) is not True:
            findings.append(
                {
                    "type": "response_deobfuscation_required",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "response_deobfuscation_required=false",
                }
            )
        hit_count = int(payload.get("response_deobfuscation_hit_count", 0) or 0)
        actual_flag = payload.get("response_deobfuscation_applied_actual")
        if not isinstance(actual_flag, bool):
            findings.append(
                {
                    "type": "response_deobfuscation_applied",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "response_deobfuscation_applied_actual must be boolean",
                }
            )
        elif actual_flag is False and hit_count > 0:
            findings.append(
                {
                    "type": "response_deobfuscation_applied",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "response_deobfuscation_applied_actual=false while hit_count>0",
                }
            )
        elif actual_flag is True and hit_count == 0:
            findings.append(
                {
                    "type": "response_deobfuscation_applied",
                    "path": str(map_file),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "response_deobfuscation_applied_actual=true while hit_count==0",
                }
            )

    if bool(policy.get("audit_log_required", False)) and map_files:
        audit_log_path = map_root / "audit_log.jsonl"
        has_audit = audit_log_path.exists()
        if has_audit:
            try:
                has_audit = bool(audit_log_path.read_text(encoding="utf-8").strip())
            except Exception:
                has_audit = False
        if not has_audit:
            findings.append(
                {
                    "type": "sanitization_audit_trail_missing",
                    "path": str(audit_log_path),
                    "line": 0,
                    "severity": "ERROR",
                    "detail": "SANITIZATION_AUDIT_TRAIL_MISSING",
                }
            )

    rid = str(run_id or "").strip()
    if rid:
        run_maps = [p for p in map_files if p.name.startswith(f"{rid}_")]
        if run_maps:
            manifest_path = map_root / f"{rid}_obfuscation_manifest.json"
            ok_manifest, manifest_issues = verify_json_manifest(manifest_path, require_manifest=True, verify_manifest_sidecar=True)
            if not ok_manifest:
                findings.append(
                    {
                        "type": "sanitization_map_manifest_invalid",
                        "path": str(manifest_path),
                        "line": 0,
                        "severity": "ERROR",
                        "detail": ",".join(manifest_issues[:5]),
                    }
                )
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-publish safety/path audit")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--out-json", default="data/agent_quality/pre_publish_audit_latest.json")
    parser.add_argument(
        "--strict",
        type=int,
        default=1,
        choices=[0, 1],
        help="Fail with non-zero exit code when ERROR findings are present.",
    )
    args = parser.parse_args()
    security_profile = load_security_profile()
    strict_manifest_scope = bool(security_profile.get("strict_manifest_scope", True))
    manifest_scope_ignore_globs = [str(x) for x in security_profile.get("manifest_scope_ignore_globs", []) if str(x).strip()]

    findings: list[dict[str, Any]] = []
    rid = args.run_id.strip()
    for path in _iter_files():
        findings.extend(_scan_text_file(path, rid))
    findings.extend(_scan_links(rid))
    findings.extend(
        _scan_json_integrity_manifest(
            rid,
            strict_manifest_scope=strict_manifest_scope,
            manifest_scope_ignore_globs=manifest_scope_ignore_globs,
        )
    )
    findings.extend(_scan_run_all_script_refs())
    findings.extend(_scan_assignment_recovery_governance(rid))
    findings.extend(_scan_v3_runtime_contracts(rid))
    findings.extend(_scan_cloud_gateway_policy())
    findings.extend(_scan_sanitization_map_policy(rid))
    findings.extend(_scan_poc_artifact_spam_policy())

    error_findings = [f for f in findings if f.get("severity") == "ERROR"]
    warn_findings = [f for f in findings if f.get("severity") == "WARN"]
    if int(args.strict) == 1 and rid:
        blocking_errors = [f for f in error_findings if _is_run_scoped_finding(f, rid)]
    else:
        blocking_errors = list(error_findings)
    passed = len(blocking_errors) == 0
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": rid or None,
        "passed": passed,
        "counts": {
            "error": len(error_findings),
            "warn": len(warn_findings),
            "blocking_error": len(blocking_errors),
            "non_blocking_error": max(0, len(error_findings) - len(blocking_errors)),
        },
        "findings": findings,
        "version": "pre_publish_audit.v1",
        "security_profile": security_profile.get("name"),
        "strict_manifest_scope": strict_manifest_scope,
    }

    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    status = "FAIL" if payload["counts"]["blocking_error"] > 0 else ("WARN" if payload["counts"]["error"] > 0 or payload["counts"]["warn"] > 0 else "PASS")
    print(
        "ok: pre_publish_audit "
        f"status={status} errors={payload['counts']['error']} "
        f"blocking_errors={payload['counts']['blocking_error']} "
        f"warns={payload['counts']['warn']}"
    )
    if int(args.strict) == 1 and payload["counts"]["blocking_error"] > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
