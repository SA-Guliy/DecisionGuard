from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path

from src.domain_template import load_experiment_variants
from src.paths import run_all_log_path
from src.paired_registry import PAIRED_RUN_STATUS_VALUES

PAIRED_RUN_STATUS = PAIRED_RUN_STATUS_VALUES


def _path_contains_run_id_token(path: Path, run_id: str) -> bool:
    token = str(run_id or "").strip()
    if not token:
        return False
    # Match run_id as token, not as arbitrary prefix substring.
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(token)}(?![A-Za-z0-9_-])")
    return bool(pattern.search(path.as_posix()))


@dataclass(frozen=True)
class RunAllRuntimeConfig:
    exp_id: str
    log_file: Path
    lightweight: bool
    llm_env: dict[str, str] | None
    domain_template: str
    mode: str = "single"
    run_id_ctrl: str = ""


def build_run_all_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run full project pipeline in one command (runtime-safe)")
    parser.add_argument("--run-id", required=True, help="Run ID")
    parser.add_argument("--mode", choices=["single", "paired"], default="single", help="Runtime mode")
    parser.add_argument(
        "--run-id-ctrl",
        default="",
        help="Control run_id for --mode paired (default: <run-id>_ctrl)",
    )
    parser.add_argument("--reload-raw", action="store_true", help="Reload RAW before simulation")
    parser.add_argument("--raw-dir", required=False, help="RAW directory (required if --reload-raw)")
    parser.add_argument("--allow-truncate-raw", type=int, default=0, choices=[0, 1])
    parser.add_argument("--enable-customer-dynamics", type=int, default=1, choices=[0, 1])
    parser.add_argument("--mode-tag", default="default")
    parser.add_argument("--horizon-days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=0, help="Deterministic simulation seed")
    parser.add_argument(
        "--domain-template",
        default="",
        help="Path to domain template JSON (required: no domain defaults in core runtime)",
    )
    parser.add_argument("--backend", choices=["groq", "ollama", "auto"], default="auto")
    parser.add_argument(
        "--allow-overwrite-run",
        type=int,
        default=0,
        choices=[0, 1],
        help="Allow replacing existing rows for the same run_id",
    )
    parser.add_argument(
        "--overwrite-reason",
        default="",
        help="Required audit reason when --allow-overwrite-run=1 and run exists",
    )
    parser.add_argument("--experiment-id", default="", help="Required experiment id for assignment + AB governance gates")
    parser.add_argument("--experiment-unit", choices=["customer", "store"], default="customer")
    parser.add_argument("--experiment-treat-pct", type=int, default=50, help="Treatment percent for deterministic assignment")
    parser.add_argument("--experiment-salt", default="", help="Optional assignment salt; default uses run_id")
    parser.add_argument(
        "--ab-primary-metric",
        default="",
        help="Primary AB metric id (optional; if empty, resolved by AB runtime contract/template)",
    )
    parser.add_argument("--ab-bootstrap-iters", type=int, default=300)
    parser.add_argument("--allow-assignment-recovery", type=int, default=0, choices=[0, 1])
    parser.add_argument("--enable-supply-realism", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-ops-noise", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-demand-shocks", type=int, default=1, choices=[0, 1])
    parser.add_argument("--enable-competitor-prices", type=int, default=0, choices=[0, 1])
    parser.add_argument("--perishable-remove-buffer-days", type=int, default=1)
    parser.add_argument("--build-weekly", type=int, default=0, choices=[0, 1])
    parser.add_argument("--build-exec", type=int, default=0, choices=[0, 1])
    parser.add_argument(
        "--lightweight-profile",
        type=int,
        default=0,
        choices=[0, 1],
        help="Run core P0 flow only to reduce CPU/RAM pressure",
    )
    parser.add_argument(
        "--verify-acceptance",
        type=int,
        default=1,
        choices=[0, 1],
        help="Run artifact-level acceptance verification at end",
    )
    parser.add_argument(
        "--enable-deepseek-doctor",
        type=int,
        default=1,
        choices=[0, 1],
        help="Use DeepSeek model route for Doctor on Groq",
    )
    parser.add_argument("--enable-react-doctor", type=int, default=0, choices=[0, 1], help="Enable protocol-gated ReAct mode for Doctor")
    parser.add_argument("--react-max-steps", type=int, default=4, help="ReAct max steps for Doctor when enabled")
    parser.add_argument("--react-timeout-sec", type=int, default=25, help="ReAct timeout (seconds) for Doctor when enabled")
    parser.add_argument("--enable-react-commander", type=int, default=0, choices=[0, 1], help="Enable protocol-gated ReAct mode for Commander")
    parser.add_argument("--react-commander-max-steps", type=int, default=4, help="ReAct max steps for Commander when enabled")
    parser.add_argument(
        "--enable-hypothesis-review-v1",
        type=int,
        default=-1,
        choices=[-1, 0, 1],
        help="Commander review ceiling mode (-1 auto: strict/prod=>1, else 0)",
    )
    parser.add_argument(
        "--allow-remote-llm",
        type=int,
        default=-1,
        choices=[-1, 0, 1],
        help="Override LLM_ALLOW_REMOTE for agent steps (-1 inherit, 0 local-only, 1 allow remote)",
    )
    parser.add_argument(
        "--require-real-llm-core-agents",
        type=int,
        default=0,
        choices=[0, 1],
        help="Fail run if Captain/Doctor/Commander are not all core-accepted real LLM outputs",
    )
    return parser


def _inject_groq_key_if_needed() -> None:
    """Silently load GROQ_API_KEY from ~/.groq_secrets into os.environ if not already set.

    Security guarantees:
    - Key value is NEVER printed, logged, or returned.
    - override=False: explicit env var always takes precedence over the file.
    - Key format is validated (gsk_ prefix, min 20 chars) before accepting.
    - File path is not disclosed in log messages.
    - Failure is non-fatal: agents fall through to deterministic fallback.
    - Key propagates to all child subprocesses via os.environ.copy() in _run_step.
    """
    existing = os.getenv("GROQ_API_KEY", "").strip()
    if existing:
        if existing.startswith("gsk_") and len(existing) >= 20:
            print("INFO: llm_key=present source=env [key hidden]")
        else:
            print("WARN: llm_key=invalid_format source=env — agents may fail cloud calls")
        return

    secrets_path = Path.home() / ".groq_secrets"
    if not secrets_path.exists():
        print("INFO: llm_key=absent source=none — agents will use deterministic fallback")
        return

    try:
        from dotenv import load_dotenv
        load_dotenv(secrets_path, override=False)
        loaded = os.getenv("GROQ_API_KEY", "").strip()
        if not loaded:
            print("INFO: llm_key=absent source=secrets_file — GROQ_API_KEY missing in file")
        elif not (loaded.startswith("gsk_") and len(loaded) >= 20):
            print("WARN: llm_key=invalid_format source=secrets_file — agents may fail cloud calls")
        else:
            print("INFO: llm_key=loaded source=secrets_file [key hidden]")
    except Exception as exc:
        print(f"INFO: llm_key=load_failed reason={type(exc).__name__} — agents will use deterministic fallback")


def resolve_run_all_runtime_config(args: argparse.Namespace) -> RunAllRuntimeConfig:
    run_id = str(getattr(args, "run_id", "") or "").strip()
    mode = str(getattr(args, "mode", "single") or "single").strip().lower()
    if mode not in {"single", "paired"}:
        raise SystemExit(f"Unsupported --mode: {mode}")
    exp_id = args.experiment_id.strip()
    if not exp_id:
        raise SystemExit(
            "EXPERIMENT_CONTEXT_REQUIRED: Provide --experiment-id <id>; run is blocked by governance policy."
        )
    domain_template = str(args.domain_template or "").strip()
    if not domain_template:
        raise SystemExit("ConfigurationError: Missing Domain Template")
    if args.reload_raw and not args.raw_dir:
        raise SystemExit("--raw-dir is required when --reload-raw is set")
    if args.allow_overwrite_run == 1 and not args.overwrite_reason.strip():
        raise SystemExit("--overwrite-reason is required when --allow-overwrite-run=1")
    if os.getenv("DS_STRICT_RUNTIME", "0") == "1" and int(args.verify_acceptance) != 1:
        raise SystemExit("--verify-acceptance=0 is forbidden when DS_STRICT_RUNTIME=1")
    if not Path(domain_template).exists():
        raise SystemExit(f"--domain-template not found: {domain_template}")
    if Path(domain_template).suffix.lower() != ".json":
        raise SystemExit("ConfigurationError: Domain Template must be a .json file")
    run_id_ctrl = ""
    if mode == "paired":
        run_id_ctrl = str(getattr(args, "run_id_ctrl", "") or "").strip() or f"{run_id}_ctrl"
        if run_id_ctrl == run_id:
            raise SystemExit("PAIRED_RUN_ID_COLLISION: run-id and run-id-ctrl must be different")
        variants = load_experiment_variants(domain_template)
        if not isinstance(variants, dict) or not isinstance(variants.get("ctrl"), dict) or not isinstance(
            variants.get("treatment"), dict
        ):
            raise SystemExit(
                "PAIRED_VARIANTS_REQUIRED: domain_template.v2 must provide experiment_variants.ctrl/treatment"
            )
        run_ids = [run_id, run_id_ctrl]
        collision_hits_by_run: dict[str, list[str]] = {run_id: [], run_id_ctrl: []}
        for rid in run_ids:
            for root_name in ("data", "reports"):
                root = Path(root_name)
                if not root.exists():
                    continue
                for hit in root.glob(f"**/*{rid}*"):
                    if hit.is_file() and _path_contains_run_id_token(hit, rid):
                        collision_hits_by_run[rid].append(str(hit))
                        if len(collision_hits_by_run[rid]) >= 8:
                            break
                if len(collision_hits_by_run[rid]) >= 8:
                    break
        parent_has_collision = bool(collision_hits_by_run[run_id])
        ctrl_has_collision = bool(collision_hits_by_run[run_id_ctrl])
        if (parent_has_collision or ctrl_has_collision) and int(args.allow_overwrite_run) != 1:
            sample_hits = collision_hits_by_run[run_id][:3] + collision_hits_by_run[run_id_ctrl][:3]
            raise SystemExit(
                "PAIRED_RUN_ID_COLLISION: existing artifacts for run_id/run_id_ctrl; "
                "set --allow-overwrite-run=1 and provide --overwrite-reason. "
                f"sample_hits={sample_hits[:5]}"
            )
        if int(args.allow_overwrite_run) == 1 and (parent_has_collision != ctrl_has_collision):
            raise SystemExit(
                "PAIRED_RUN_ID_COLLISION: partial overwrite forbidden in paired mode; "
                "overwrite must apply atomically to both parent and ctrl runs."
            )

    _inject_groq_key_if_needed()

    lightweight = int(args.lightweight_profile) == 1
    llm_env = None
    if args.allow_remote_llm in {0, 1}:
        llm_env = {"LLM_ALLOW_REMOTE": str(args.allow_remote_llm)}
    elif lightweight and args.backend != "groq":
        llm_env = {"LLM_ALLOW_REMOTE": "0"}

    return RunAllRuntimeConfig(
        exp_id=exp_id,
        log_file=run_all_log_path(args.run_id),
        lightweight=lightweight,
        llm_env=llm_env,
        domain_template=domain_template,
        mode=mode,
        run_id_ctrl=run_id_ctrl,
    )
