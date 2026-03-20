from __future__ import annotations

from pathlib import Path

from src.run_output_paths import iter_run_completion_summary_paths


def print_run_completion_summary(
    *,
    run_id: str,
    experiment_id: str,
    log_file: Path,
    clean_layer_enabled: bool,
    missing_views: list[str],
    valid_orders_count: int | str,
) -> None:
    print("run completed")
    print(f"run_id: {run_id}")
    for label, path in iter_run_completion_summary_paths(run_id, experiment_id):
        print(f"{label}: {path}")
    print(f"run_log: {log_file}")
    print(f"CLEAN_LAYER={'enabled' if clean_layer_enabled else 'disabled'}")
    if missing_views:
        print(f"missing_views: {','.join(missing_views)}")
    print(f"valid_orders: {valid_orders_count}")
