from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timezone
from typing import Any

from src.architecture_v3 import SANITIZATION_TRANSFORM_PATH, load_json_with_integrity

_PATTERN_GROUPS: dict[str, list[re.Pattern[str]]] = {
    "secrets": [
        re.compile(r"gsk_[A-Za-z0-9_\-]+"),
        re.compile(r"postgresql://\S+", re.IGNORECASE),
        re.compile(r"([A-Za-z0-9_]*_API_KEY)\s*=\s*\S+", re.IGNORECASE),
        re.compile(r"(password\s*=\s*)\S+", re.IGNORECASE),
        re.compile(r"(token\s*=\s*)\S+", re.IGNORECASE),
    ],
    "identifiers": [
        re.compile(r"\b[vV]\d+_[A-Za-z0-9_\-]+\b"),
        re.compile(r"\bexp[_\-]?[A-Za-z0-9_\-]+\b", re.IGNORECASE),
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
    ],
    "numeric_values": [
        re.compile(r"(?<![A-Za-z0-9_])[-+]?\d+(?:\.\d+)?%?(?![A-Za-z0-9_])"),
    ],
}


def load_sanitization_transform_contract() -> dict[str, Any]:
    payload = load_json_with_integrity(SANITIZATION_TRANSFORM_PATH)
    required = {
        "version",
        "transform_mode",
        "placeholder_prefix",
        "max_replacements_per_text",
        "require_vectorization_for_cloud",
        "response_deobfuscation_required",
        "pattern_groups",
    }
    missing = [k for k in sorted(required) if k not in payload]
    if missing:
        raise RuntimeError(f"SANITIZATION_REQUIRED_FOR_CLOUD:missing_transform_contract_fields:{','.join(missing)}")
    if str(payload.get("version", "")).strip() != "sanitization_transform_v1":
        raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:invalid_transform_contract_version")
    if str(payload.get("transform_mode", "")).strip() != "vectorized_placeholder_map":
        raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:invalid_transform_mode")
    groups = payload.get("pattern_groups") if isinstance(payload.get("pattern_groups"), list) else []
    if not groups:
        raise RuntimeError("SANITIZATION_REQUIRED_FOR_CLOUD:empty_pattern_groups")
    unknown = [g for g in groups if str(g) not in _PATTERN_GROUPS]
    if unknown:
        raise RuntimeError(f"SANITIZATION_REQUIRED_FOR_CLOUD:unknown_pattern_groups:{','.join(sorted(set(map(str, unknown))))}")
    return payload


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def apply_transform(text: str, *, scope: str) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    cfg = load_sanitization_transform_contract()
    placeholder_prefix = str(cfg.get("placeholder_prefix", "__SAN")).strip() or "__SAN"
    max_replacements = int(cfg.get("max_replacements_per_text", 500) or 500)
    groups = [str(x) for x in cfg.get("pattern_groups", []) if str(x).strip()]

    result = str(text or "")
    replacements: list[dict[str, Any]] = []
    idx = 0

    for group in groups:
        for pat in _PATTERN_GROUPS[group]:
            def _repl(match: re.Match[str]) -> str:
                nonlocal idx
                if idx >= max_replacements:
                    return match.group(0)
                idx += 1
                placeholder = f"{placeholder_prefix}_{scope.upper()}_{idx}__"
                original = match.group(0)
                replacements.append(
                    {
                        "placeholder": placeholder,
                        "scope": scope,
                        "category": group,
                        "pattern": pat.pattern,
                        "original": original,
                        "original_sha256": _sha256_text(original),
                    }
                )
                return placeholder

            result = pat.sub(_repl, result)

    meta = {
        "transform_contract_version": str(cfg.get("version", "")),
        "vectorization_applied": bool(replacements),
        "replacement_count": len(replacements),
        "response_deobfuscation_required": bool(cfg.get("response_deobfuscation_required", True)),
        "require_vectorization_for_cloud": bool(cfg.get("require_vectorization_for_cloud", True)),
    }
    return result, replacements, meta


def deobfuscate_response(text: str, replacements: list[dict[str, Any]]) -> tuple[str, int]:
    value = str(text or "")
    applied = 0
    for row in replacements:
        placeholder = str(row.get("placeholder", "")).strip()
        original = str(row.get("original", ""))
        if not placeholder:
            continue
        if placeholder in value:
            value = value.replace(placeholder, original)
            applied += 1
    return value, applied


def _kms_master_secret(kms_key_ref: str) -> str:
    env_secret = str(os.getenv("SANITIZATION_KMS_MASTER_KEY", "")).strip()
    if env_secret:
        return env_secret
    raise RuntimeError(
        "SANITIZATION_MAP_POLICY_VIOLATION:missing_kms_master_secret:"
        f"{str(kms_key_ref).strip() or 'unknown_kms_ref'}"
    )


def _openssl_encrypt_bytes(plaintext: bytes, *, passphrase: str) -> str:
    if not passphrase:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:empty_encryption_passphrase")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (passphrase + "\n").encode("utf-8"))
        os.close(write_fd)
        write_fd = -1
        cmd = [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-a",
            "-A",
            "-pass",
            f"fd:{read_fd}",
        ]
        proc = subprocess.run(cmd, input=plaintext, capture_output=True, pass_fds=(read_fd,))
    finally:
        if write_fd != -1:
            try:
                os.close(write_fd)
            except Exception:
                pass
        try:
            os.close(read_fd)
        except Exception:
            pass
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="ignore").strip()
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:encryption_failed:{err[:160]}")
    return proc.stdout.decode("utf-8", errors="ignore").strip()


def _openssl_decrypt_to_bytes(ciphertext_b64: str, *, passphrase: str) -> bytes:
    if not passphrase:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:empty_decryption_passphrase")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (passphrase + "\n").encode("utf-8"))
        os.close(write_fd)
        write_fd = -1
        cmd = [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-a",
            "-A",
            "-pass",
            f"fd:{read_fd}",
        ]
        proc = subprocess.run(
            cmd,
            input=str(ciphertext_b64).encode("utf-8"),
            capture_output=True,
            pass_fds=(read_fd,),
        )
    finally:
        if write_fd != -1:
            try:
                os.close(write_fd)
            except Exception:
                pass
        try:
            os.close(read_fd)
        except Exception:
            pass
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="ignore").strip()
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:decryption_failed:{err[:160]}")
    return proc.stdout


def encrypt_payload_envelope(payload: dict[str, Any], *, kms_key_ref: str) -> dict[str, Any]:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(serialized).hexdigest()

    data_key = secrets.token_urlsafe(48)
    ciphertext_b64 = _openssl_encrypt_bytes(serialized, passphrase=data_key)

    kms_secret = _kms_master_secret(kms_key_ref)
    encrypted_data_key_b64 = _openssl_encrypt_bytes(data_key.encode("utf-8"), passphrase=kms_secret)

    envelope = {
        "algorithm": "openssl_aes_256_cbc_pbkdf2",
        "kms_key_ref": str(kms_key_ref),
        "encrypted_data_key_b64": encrypted_data_key_b64,
        "ciphertext_b64": ciphertext_b64,
        "payload_sha256": payload_sha256,
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
    }
    return envelope


def decrypt_payload_envelope(envelope: dict[str, Any], *, kms_key_ref: str) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:invalid_envelope")
    if str(envelope.get("kms_key_ref", "")).strip() != str(kms_key_ref).strip():
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:kms_key_ref_mismatch")
    encrypted_data_key_b64 = str(envelope.get("encrypted_data_key_b64", "")).strip()
    ciphertext_b64 = str(envelope.get("ciphertext_b64", "")).strip()
    expected_sha = str(envelope.get("payload_sha256", "")).strip().lower()
    if not encrypted_data_key_b64 or not ciphertext_b64 or not expected_sha:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:missing_envelope_fields")

    kms_secret = _kms_master_secret(kms_key_ref)
    data_key = _openssl_decrypt_to_bytes(encrypted_data_key_b64, passphrase=kms_secret).decode("utf-8", errors="ignore")
    plaintext = _openssl_decrypt_to_bytes(ciphertext_b64, passphrase=data_key)
    actual_sha = hashlib.sha256(plaintext).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:payload_sha256_mismatch")
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"SANITIZATION_MAP_POLICY_VIOLATION:decrypted_payload_invalid_json:{exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("SANITIZATION_MAP_POLICY_VIOLATION:decrypted_payload_not_object")
    return payload


def verify_encrypted_map_document(doc: dict[str, Any], *, kms_key_ref: str, require_roundtrip: bool = True) -> tuple[bool, str]:
    if not isinstance(doc, dict):
        return False, "invalid_map_doc"
    if bool(doc.get("encrypted_at_rest", False)) is not True:
        return False, "encrypted_at_rest_false"
    envelope = doc.get("envelope")
    if not isinstance(envelope, dict):
        return False, "missing_envelope"
    for key in ("algorithm", "encrypted_data_key_b64", "ciphertext_b64", "payload_sha256", "kms_key_ref"):
        if not str(envelope.get(key, "")).strip():
            return False, f"missing_envelope_field:{key}"
    if str(envelope.get("algorithm", "")).strip() != "openssl_aes_256_cbc_pbkdf2":
        return False, "invalid_envelope_algorithm"
    if str(envelope.get("kms_key_ref", "")).strip() != str(kms_key_ref).strip():
        return False, "kms_key_ref_mismatch"
    if "payload" in doc:
        return False, "plaintext_payload_forbidden"
    if require_roundtrip:
        try:
            _ = decrypt_payload_envelope(envelope, kms_key_ref=kms_key_ref)
        except Exception as exc:
            return False, str(exc)
    return True, "ok"
