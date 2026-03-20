#!/usr/bin/env python3
from __future__ import annotations

import argparse
import tarfile
from datetime import datetime, timezone
from pathlib import Path


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _select_log_files(log_dir: Path, keep_latest: int, keep_run_id: str) -> list[Path]:
    files = [p for p in log_dir.glob("*.log") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    keep = set(files[:keep_latest])
    out: list[Path] = []
    for p in files:
        if p in keep:
            continue
        if keep_run_id and keep_run_id in p.name:
            continue
        out.append(p)
    return out


def _select_report_dirs(root: Path, keep_latest: int, keep_run_id: str) -> list[Path]:
    dirs = [p for p in root.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    keep = set(dirs[:keep_latest])
    out: list[Path] = []
    for d in dirs:
        if d in keep:
            continue
        if keep_run_id and keep_run_id in d.name:
            continue
        out.append(d)
    return out


def _archive_paths(paths: list[Path], tar_path: Path) -> None:
    with tarfile.open(tar_path, "w:gz") as tar:
        for p in paths:
            tar.add(p, arcname=p.as_posix())


def _delete_paths(paths: list[Path]) -> None:
    for p in paths:
        if p.is_file():
            p.unlink(missing_ok=True)
            continue
        if p.is_dir():
            for child in sorted(p.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    try:
                        child.rmdir()
                    except OSError:
                        pass
            try:
                p.rmdir()
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Archive old logs or report folders to reduce workspace clutter")
    parser.add_argument("--kind", choices=["logs", "reports"], required=True, help="What to archive")
    parser.add_argument("--keep-latest", type=int, default=-1, help="Override default keep count")
    parser.add_argument("--keep-run-id", default="")
    parser.add_argument("--archive-dir", default="data/archive")
    parser.add_argument("--delete-originals", type=int, default=1, choices=[0, 1])
    parser.add_argument("--log-dir", default="data/logs", help="Used when --kind logs")
    parser.add_argument("--reports-root", default="reports/L1_ops", help="Used when --kind reports")
    args = parser.parse_args()

    keep_run_id = args.keep_run_id.strip()
    archive_dir = Path(args.archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    keep_latest = args.keep_latest

    if args.kind == "logs":
        root = Path(args.log_dir)
        if not root.exists():
            print(f"ok: nothing to archive ({root} missing)")
            return
        selected = _select_log_files(root, 20 if keep_latest < 0 else max(0, keep_latest), keep_run_id)
        if not selected:
            print("ok: no old logs selected for archival")
            return
        tar_path = archive_dir / f"logs_archive_{_timestamp()}.tar.gz"
        _archive_paths(selected, tar_path)
        if int(args.delete_originals) == 1:
            _delete_paths(selected)
        print(
            f"ok: kind=logs archived={len(selected)} archive={tar_path} "
            f"deleted={int(args.delete_originals)==1}"
        )
        return

    root = Path(args.reports_root)
    if not root.exists():
        print(f"ok: reports root missing ({root})")
        return
    selected = _select_report_dirs(root, 12 if keep_latest < 0 else max(0, keep_latest), keep_run_id)
    if not selected:
        print("ok: no old report folders selected")
        return
    tar_path = archive_dir / f"reports_l1_archive_{_timestamp()}.tar.gz"
    _archive_paths(selected, tar_path)
    if int(args.delete_originals) == 1:
        _delete_paths(selected)
    print(
        f"ok: kind=reports archived={len(selected)} archive={tar_path} "
        f"deleted={int(args.delete_originals)==1}"
    )


if __name__ == "__main__":
    main()
