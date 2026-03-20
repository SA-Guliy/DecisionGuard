#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


HUMAN_FILES = [
    "index.md",
    "decision_card.md",
    "RETAIL_MBR.md",
    "MBR_SUMMARY.md",
    "CAUSAL_EXPLANATION.md",
    "AGENT_VALUE_SCORECARD.md",
    "ACCEPTANCE_REPORT.md",
    "agent_governance.md",
    "synthetic_realism.md",
    "synthetic_bias.md",
]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_hub_entry(run_id: str) -> None:
    src_run = Path(f"reports/L1_ops/{run_id}")
    dst_run = Path(f"human_reports/L1/{run_id}")
    dst_run.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# Human Pack — {run_id}",
        "",
        "Open these first:",
        "",
    ]
    for name in HUMAN_FILES:
        src = src_run / name
        if src.exists():
            rel = f"../../../reports/L1_ops/{run_id}/{name}"
            lines.append(f"- [{name}]({rel})")
    chart = src_run / "charts"
    if chart.exists():
        lines.append(f"- [charts/](../../../reports/L1_ops/{run_id}/charts/)")
    _write(dst_run / "index.md", "\n".join(lines) + "\n")


def _build_root_index(run_ids: list[str]) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Human Reports Hub",
        "",
        f"Generated at: `{ts}`",
        "",
        "## L1 Run Packs",
    ]
    for rid in run_ids:
        lines.append(f"- [{rid}](L1/{rid}/index.md)")
    lines.extend(
        [
            "",
            "## L2 Management",
            "- [reports/L2_mgmt/](../reports/L2_mgmt/)",
            "",
            "## L3 Exec",
            "- [reports/L3_exec/](../reports/L3_exec/)",
        ]
    )
    _write(Path("human_reports/README.md"), "\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build human-facing report hub (non-destructive)")
    parser.add_argument("--run-id", default="", help="Optional run id to refresh only one L1 pack")
    args = parser.parse_args()

    l1_root = Path("reports/L1_ops")
    if not l1_root.exists():
        print("WARN: reports/L1_ops missing; nothing to build")
        return

    if args.run_id.strip():
        run_ids = [args.run_id.strip()]
    else:
        run_ids = sorted([p.name for p in l1_root.iterdir() if p.is_dir()])

    for rid in run_ids:
        if (l1_root / rid).exists():
            _run_hub_entry(rid)

    _build_root_index(run_ids)
    print(f"ok: human hub updated ({len(run_ids)} run packs)")


if __name__ == "__main__":
    main()
