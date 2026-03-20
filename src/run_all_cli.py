from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

from src.paths import run_all_log_path


@dataclass(frozen=True)
class RunAllRuntimeConfig:
    exp_id: str
    log_file: Path
    lightweight: bool
    llm_env: dict[str, str] | None
    domain_template: str


def build_run_all_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run full project pipeline in one command (runtime-safe)")
    parser.add_argument("--run-id", required=True, help="Run ID")
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
    parser.add_argument("--experiment-id", default="", help="Optional experiment id for assignment + AB analysis")
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


def resolve_run_all_runtime_config(args: argparse.Namespace) -> RunAllRuntimeConfig:
    exp_id = args.experiment_id.strip()
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
    )
