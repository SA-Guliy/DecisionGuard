from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from src.architecture_v3 import SANITIZATION_POLICY_PATH, SANITIZATION_TRANSFORM_PATH, load_json_with_integrity
from src.llm_client import get_llm_backend as _raw_get_llm_backend
from src.sanitization_transform import (
    apply_transform,
    deobfuscate_response,
    encrypt_payload_envelope,
    load_sanitization_transform_contract,
    verify_encrypted_map_document,
)
from src.security_utils import verify_sha256_sidecar, write_json_manifest, write_sha256_sidecar

_ALLOWED_MAP_ROOT = Path("data/security/obfuscation_maps")
_FORBIDDEN_MAP_ROOTS = (
    Path("reports"),
    Path("human_reports"),
    Path("data/agent_reports"),
)


def _is_cloud_backend_name(name: str) -> bool:
    return str(name or "").strip().lower() in {"groq"}


def _is_cloud_backend_instance(backend: Any) -> bool:
    return backend.__class__.__name__ == "GroqBackend"


def _load_sanitization_policy() -> dict[str, Any]:
    payload = load_json_with_integrity(SANITIZATION_POLICY_PATH)
    required = {
        "storage_policy",
        "encrypted_at_rest",
        "encryption_algorithm",
        "kms_key_ref",
        "kms_envelope_required",
        "acl_enforced",
        "ttl_hours",
        "allowed_readers",
        "key_rotation_days",
        "decrypt_roundtrip_required",
        "audit_log_required",
    }
    missing = [k for k in sorted(required) if k not in payload]
    if missing:
        raise RuntimeError(f"SANITIZATION_REQUIRED_FOR_CLOUD:missing_policy_fields:{','.join(missing)}")
    if payload.get("storage_policy") != "security_obfuscation_map_only":
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:invalid_storage_policy")
    if bool(payload.get("encrypted_at_rest", False)) is not True:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:encrypted_at_rest_must_be_true")
    if str(payload.get("encryption_algorithm", "")).strip() != "openssl_aes_256_cbc_pbkdf2":
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:invalid_encryption_algorithm")
    if bool(payload.get("kms_envelope_required", False)) is not True:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:kms_envelope_required_must_be_true")
    if bool(payload.get("acl_enforced", False)) is not True:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:acl_enforced_must_be_true")
    if bool(payload.get("audit_log_required", False)) is not True:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:audit_log_required_must_be_true")
    if bool(payload.get("decrypt_roundtrip_required", False)) is not True:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:decrypt_roundtrip_required_must_be_true")
    if not isinstance(payload.get("allowed_readers"), list) or not payload.get("allowed_readers"):
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:allowed_readers_empty")
    if int(payload.get("ttl_hours", 0) or 0) <= 0:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:invalid_ttl_hours")
    return payload


def _enforce_policy_acl(policy: dict[str, Any]) -> None:
    allowed = [str(x).strip() for x in policy.get("allowed_readers", []) if str(x).strip()]
    if not allowed:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:allowed_readers_empty")
    reader = str(os.getenv("SANITIZATION_READER_ROLE", "runtime_orchestrator")).strip()
    if reader not in allowed:
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:reader_not_allowed:{reader}")


def _validate_obfuscation_map_path(path: Path) -> None:
    p = path.resolve()
    allowed = _ALLOWED_MAP_ROOT.resolve()
    try:
        p.relative_to(allowed)
    except Exception as exc:
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:map_path_outside_allowed_root:{path}") from exc

    for forbidden in _FORBIDDEN_MAP_ROOTS:
        f = forbidden.resolve()
        try:
            p.relative_to(f)
        except Exception:
            continue
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:forbidden_map_location:{path}")


def _purge_expired_obfuscation_maps(*, now_utc: datetime) -> None:
    if not _ALLOWED_MAP_ROOT.exists():
        return
    for p in sorted(_ALLOWED_MAP_ROOT.glob("*_*.json")):
        if not p.is_file():
            continue
        if p.name.endswith("_manifest.json"):
            continue
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        expires_at = str(payload.get("expires_at", "")).strip()
        if not expires_at:
            continue
        try:
            ts = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            continue
        if ts >= now_utc:
            continue
        try:
            p.unlink(missing_ok=True)
        except Exception:
            continue
        sidecar = Path(f"{p}.sha256")
        if sidecar.exists():
            sidecar.unlink(missing_ok=True)


def _register_obfuscation_manifest(run_id: str) -> None:
    run_prefix = f"{run_id}_"
    artifacts = [
        p
        for p in sorted(_ALLOWED_MAP_ROOT.glob(f"{run_prefix}*.json"))
        if p.is_file() and not p.name.endswith("_manifest.json")
    ]
    manifest_path = _ALLOWED_MAP_ROOT / f"{run_id}_obfuscation_manifest.json"
    write_json_manifest(manifest_path, artifacts, run_id=run_id)
    ok_manifest, reason = verify_sha256_sidecar(manifest_path, required=True)
    if not ok_manifest:
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:manifest_integrity_failed:{reason}")


def get_llm_backend(
    backend_name: Optional[str] = None,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Any:
    """Single allowed gateway for cloud/backend selection in runtime scripts."""
    requested = str(backend_name or "").strip().lower()
    if _is_cloud_backend_name(requested):
        policy = _load_sanitization_policy()
        _enforce_policy_acl(policy)
        _ = load_sanitization_transform_contract()
    backend = _raw_get_llm_backend(
        backend_name=backend_name,
        model_name=model_name,
        api_key=api_key,
    )
    if _is_cloud_backend_instance(backend):
        policy = _load_sanitization_policy()
        _enforce_policy_acl(policy)
        _ = load_sanitization_transform_contract()
    return backend


def gateway_generate(
    *,
    backend: Any,
    run_id: str,
    agent_name: str,
    call_name: str,
    prompt: str,
    system_prompt: str,
) -> tuple[str, dict[str, Any]]:
    meta: dict[str, Any] = {
        "cloud_path": False,
        "obfuscation_map_ref": "",
        "model": str(getattr(backend, "get_model_name", lambda: "unknown")() or "unknown"),
    }
    if not _is_cloud_backend_instance(backend):
        meta["sanitization_vectorization_applied"] = False
        meta["response_deobfuscation_required"] = False
        meta["response_deobfuscation_applied_actual"] = False
        meta["response_deobfuscation_applied"] = False
        return str(backend.generate(prompt=prompt, system_prompt=system_prompt) or ""), meta

    policy = _load_sanitization_policy()
    _enforce_policy_acl(policy)
    transform_contract = load_sanitization_transform_contract()
    meta["cloud_path"] = True

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    map_name = f"{agent_name}_{call_name}_{ts}"
    safe_prompt, prompt_map, prompt_meta = apply_transform(str(prompt or ""), scope="prompt")
    safe_system, system_map, system_meta = apply_transform(str(system_prompt or ""), scope="system")

    all_replacements = [*prompt_map, *system_map]
    vectorization_applied = bool(prompt_meta.get("vectorization_applied") or system_meta.get("vectorization_applied"))
    if bool(transform_contract.get("require_vectorization_for_cloud", True)) and not vectorization_applied:
        raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:vectorization_not_applied")

    response_deobf_required = bool(transform_contract.get("response_deobfuscation_required", True))
    try:
        cloud_output = str(backend.generate(prompt=safe_prompt, system_prompt=safe_system) or "")
        output, deobf_count = deobfuscate_response(cloud_output, all_replacements)
        response_deobf_applied_actual = bool(deobf_count > 0)
    except Exception as exc:
        map_payload = {
            "agent_name": agent_name,
            "call_name": call_name,
            "model": meta["model"],
            "status": "error",
            "error": str(exc),
            "prompt_sha256": hashlib.sha256(safe_prompt.encode("utf-8")).hexdigest(),
            "system_prompt_sha256": hashlib.sha256(safe_system.encode("utf-8")).hexdigest(),
            "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
            "sanitization_vectorization_applied": vectorization_applied,
            "response_deobfuscation_required": response_deobf_required,
            "response_deobfuscation_applied_actual": False,
            "response_deobfuscation_applied": False,
            "response_deobfuscation_hit_count": 0,
            "replacements": {
                "prompt": prompt_map,
                "system": system_map,
            },
        }
        map_path = write_obfuscation_map(run_id=run_id, map_name=map_name, payload=map_payload)
        meta["obfuscation_map_ref"] = str(map_path)
        raise

    map_payload = {
        "agent_name": agent_name,
        "call_name": call_name,
        "model": meta["model"],
        "status": "ok",
        "prompt_sha256": hashlib.sha256(safe_prompt.encode("utf-8")).hexdigest(),
        "system_prompt_sha256": hashlib.sha256(safe_system.encode("utf-8")).hexdigest(),
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
        "sanitization_vectorization_applied": vectorization_applied,
        "response_deobfuscation_required": response_deobf_required,
        "response_deobfuscation_applied_actual": response_deobf_applied_actual,
        "response_deobfuscation_applied": response_deobf_applied_actual,
        "response_deobfuscation_hit_count": int(deobf_count),
        "replacements": {
            "prompt": prompt_map,
            "system": system_map,
        },
    }
    map_path = write_obfuscation_map(run_id=run_id, map_name=map_name, payload=map_payload)
    meta["obfuscation_map_ref"] = str(map_path)
    meta["sanitization_vectorization_applied"] = vectorization_applied
    meta["response_deobfuscation_required"] = response_deobf_required
    meta["response_deobfuscation_applied_actual"] = response_deobf_applied_actual
    meta["response_deobfuscation_applied"] = response_deobf_applied_actual
    return output, meta


def gateway_chat_completion(
    *,
    backend: Any,
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.2,
    run_id: str | None = None,
    agent_name: str | None = None,
    call_name: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Gateway-safe completion call with usage metadata.

    This function intentionally hides direct SDK access from runtime scripts.
    """
    if _is_cloud_backend_instance(backend) and hasattr(backend, "_client"):
        policy = _load_sanitization_policy()
        _enforce_policy_acl(policy)
        transform_contract = load_sanitization_transform_contract()

        run_id_norm = str(run_id or "").strip()
        agent_name_norm = str(agent_name or "").strip() or "unknown_agent"
        call_name_norm = str(call_name or "").strip() or "chat_completion"
        if not run_id_norm:
            raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:missing_run_id_for_chat_completion")

        safe_system, system_map, system_meta = apply_transform(str(system_prompt or ""), scope="system")
        safe_user, user_map, user_meta = apply_transform(str(user_prompt or ""), scope="prompt")
        all_replacements = [*system_map, *user_map]
        vectorization_applied = bool(system_meta.get("vectorization_applied") or user_meta.get("vectorization_applied"))
        if bool(transform_contract.get("require_vectorization_for_cloud", True)) and not vectorization_applied:
            raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:vectorization_not_applied")

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        map_name = f"{agent_name_norm}_{call_name_norm}_{ts}"
        model_name = str(getattr(backend, "get_model_name", lambda: "unknown")() or "unknown")
        try:
            chat = backend._client.chat.completions.create(  # type: ignore[attr-defined]
                model=model_name,
                messages=[
                    {"role": "system", "content": safe_system},
                    {"role": "user", "content": safe_user},
                ],
                temperature=float(temperature),
            )
            cloud_content = str(chat.choices[0].message.content or "")
            content, deobf_count = deobfuscate_response(cloud_content, all_replacements)
            response_deobf_required = bool(transform_contract.get("response_deobfuscation_required", True))
            response_deobf_applied_actual = bool(deobf_count > 0)
            usage = getattr(chat, "usage", None)
            prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
            completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
            total_tokens = int(
                getattr(usage, "total_tokens", prompt_tokens + completion_tokens) or (prompt_tokens + completion_tokens)
            )
            map_payload = {
                "agent_name": agent_name_norm,
                "call_name": call_name_norm,
                "model": model_name,
                "status": "ok",
                "prompt_sha256": hashlib.sha256(safe_user.encode("utf-8")).hexdigest(),
                "system_prompt_sha256": hashlib.sha256(safe_system.encode("utf-8")).hexdigest(),
                "output_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
                "sanitization_vectorization_applied": vectorization_applied,
                "response_deobfuscation_required": response_deobf_required,
                "response_deobfuscation_applied_actual": response_deobf_applied_actual,
                "response_deobfuscation_applied": response_deobf_applied_actual,
                "response_deobfuscation_hit_count": int(deobf_count),
                "replacements": {
                    "prompt": user_map,
                    "system": system_map,
                },
            }
            map_path = write_obfuscation_map(run_id=run_id_norm, map_name=map_name, payload=map_payload)
            return content, {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "cloud_path": 1,
                "obfuscation_map_ref": str(map_path),
                "sanitization_vectorization_applied": vectorization_applied,
                "response_deobfuscation_required": response_deobf_required,
                "response_deobfuscation_applied_actual": response_deobf_applied_actual,
                "response_deobfuscation_applied": response_deobf_applied_actual,
            }
        except Exception as exc:
            map_payload = {
                "agent_name": agent_name_norm,
                "call_name": call_name_norm,
                "model": model_name,
                "status": "error",
                "error": str(exc),
                "prompt_sha256": hashlib.sha256(safe_user.encode("utf-8")).hexdigest(),
                "system_prompt_sha256": hashlib.sha256(safe_system.encode("utf-8")).hexdigest(),
                "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
                "sanitization_vectorization_applied": vectorization_applied,
                "response_deobfuscation_required": bool(transform_contract.get("response_deobfuscation_required", True)),
                "response_deobfuscation_applied_actual": False,
                "response_deobfuscation_applied": False,
                "response_deobfuscation_hit_count": 0,
                "replacements": {
                    "prompt": user_map,
                    "system": system_map,
                },
            }
            _ = write_obfuscation_map(run_id=run_id_norm, map_name=map_name, payload=map_payload)
            raise

    text = backend.generate(user_prompt, system_prompt=system_prompt)
    prompt_tokens = max(1, int((len(system_prompt) + len(user_prompt)) / 4))
    completion_tokens = max(1, int(len(str(text or "")) / 4))
    return str(text or ""), {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "cloud_path": 0,
        "obfuscation_map_ref": "",
        "sanitization_vectorization_applied": False,
        "response_deobfuscation_required": False,
        "response_deobfuscation_applied_actual": False,
        "response_deobfuscation_applied": False,
    }


def write_obfuscation_map(
    *,
    run_id: str,
    map_name: str,
    payload: dict[str, Any],
) -> Path:
    policy = _load_sanitization_policy()
    _enforce_policy_acl(policy)
    _ = load_sanitization_transform_contract()

    _purge_expired_obfuscation_maps(now_utc=datetime.now(timezone.utc))
    safe_name = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(map_name or "map"))
    out = _ALLOWED_MAP_ROOT / f"{run_id}_{safe_name}.json"
    _validate_obfuscation_map_path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    envelope = encrypt_payload_envelope(payload, kms_key_ref=str(policy.get("kms_key_ref", "")))
    doc = {
        "version": "obfuscation_map_v2",
        "run_id": run_id,
        "map_name": safe_name,
        "policy_ref": str(SANITIZATION_POLICY_PATH),
        "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
        "encrypted_at_rest": bool(policy.get("encrypted_at_rest", True)),
        "encryption_algorithm": str(policy.get("encryption_algorithm", "")),
        "kms_key_ref": str(policy.get("kms_key_ref", "")),
        "acl_enforced": bool(policy.get("acl_enforced", True)),
        "allowed_readers": list(policy.get("allowed_readers", [])) if isinstance(policy.get("allowed_readers"), list) else [],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=int(policy.get("ttl_hours", 24)))).isoformat(),
        "sanitization_vectorization_applied": bool(payload.get("sanitization_vectorization_applied", False)),
        "response_deobfuscation_required": bool(payload.get("response_deobfuscation_required", False)),
        "response_deobfuscation_applied_actual": bool(payload.get("response_deobfuscation_applied_actual", False)),
        "response_deobfuscation_hit_count": int(payload.get("response_deobfuscation_hit_count", 0) or 0),
        "response_deobfuscation_applied": bool(payload.get("response_deobfuscation_applied", False)),
        "envelope": envelope,
    }
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    write_sha256_sidecar(out)

    enc_ok, enc_reason = verify_encrypted_map_document(
        doc,
        kms_key_ref=str(policy.get("kms_key_ref", "")),
        require_roundtrip=bool(policy.get("decrypt_roundtrip_required", True)),
    )
    if not enc_ok:
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:{enc_reason}")

    _register_obfuscation_manifest(run_id)

    audit_path = _ALLOWED_MAP_ROOT / "audit_log.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fp:
        fp.write(
            json.dumps(
                {
                    "event": "obfuscation_map_write",
                    "run_id": run_id,
                    "path": str(out),
                    "policy_ref": str(SANITIZATION_POLICY_PATH),
                    "transform_contract_ref": str(SANITIZATION_TRANSFORM_PATH),
                    "map_encryption_verified": enc_ok,
                    "map_encryption_reason": enc_reason,
                    "ts": datetime.now(timezone.utc).isoformat(),
                },
                ensure_ascii=False,
            )
            + "\n"
        )
    return out
