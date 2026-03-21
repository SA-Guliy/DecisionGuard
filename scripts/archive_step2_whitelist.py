#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
ARCHIVE_DIR = DATA_DIR / "archive"

WHITELIST_RUNS = {"v13_agent_prod_013", "v13_agent_prod_011"}
REPORTS_PREFIXES = (
    "v13_ab_final_",
    "v13_ab_fix_",
    "v13_agent_canary_",
    "v13_agent_shadow_",
    "v13_agent_value_",
    "v13_ens_",
    "v13_proof_",
)
REPORTS_EXACT = {"v13_agent_prod_002", "v13_agent_prod_003"}

ACTIVE_DOCS_P0 = {
    "ab_methodology_spec.md",
    "ab_data_contract_v1.md",
    "metrics_contract_v1.md",
}

INVALID_AB_STATUSES = {
    "MISSING_ASSIGNMENT",
    "UNOBSERVABLE",
    "BLOCKED_BY_DATA",
    "INVALID_METHODS",
}

CANONICAL_BASENAMES = {
    "канонический_стандарт.md",
    "AB_stat_report_standart.md",
    "Decision Card_standard.md",
    "AB_STAT_REPORT_CANONICAL.md",
    "DECISION_CARD_CANONICAL.md",
    "STANDARD_CONFORMANCE.md",
}


@dataclass
class ArchiveAction:
    label: str
    archive_path: Path
    sources: list[Path]
    preserved: list[Path]


def _existing_sources(paths: Iterable[Path]) -> list[Path]:
    return [p for p in paths if p.exists()]


def _dedupe_nested(paths: Iterable[Path]) -> list[Path]:
    ordered = sorted(set(paths), key=lambda p: (len(p.parts), p.as_posix()))
    keep: list[Path] = []
    kept_dirs: list[Path] = []
    for path in ordered:
        if any(parent in path.parents for parent in kept_dirs):
            continue
        keep.append(path)
        if path.is_dir():
            kept_dirs.append(path)
    return keep


def _unique_archive_path(target: Path) -> Path:
    if not target.exists():
        return target
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return target.with_name(f"{target.stem}_{stamp}{target.suffix}")


def _is_in_archive_dir(path: Path) -> bool:
    try:
        path.resolve().relative_to(ARCHIVE_DIR.resolve())
        return True
    except ValueError:
        return False


def _is_pinned(path: Path, pinned: set[Path]) -> bool:
    resolved = path.resolve()
    if resolved in pinned:
        return True
    return any(parent in pinned for parent in resolved.parents)


def _is_canonical_or_protected(path: Path) -> bool:
    if path.name in CANONICAL_BASENAMES:
        return True
    upper = path.name.upper()
    return "CANONICAL" in upper or "PROTECTED" in upper


def _split_archivable_paths(
    root: Path,
    is_protected: Callable[[Path], bool],
) -> tuple[list[Path], list[Path]]:
    descendants = sorted(root.rglob("*"), key=lambda p: (len(p.parts), p.as_posix()))
    protected: list[Path] = []
    blocked_dirs: set[Path] = set()

    for item in descendants:
        if not is_protected(item):
            continue
        protected.append(item)
        for parent in item.parents:
            if parent == root.parent:
                break
            blocked_dirs.add(parent)

    if not protected and not is_protected(root):
        return [root], []

    archivable: list[Path] = []
    for item in descendants:
        if is_protected(item):
            continue
        if item.is_dir() and item in blocked_dirs:
            continue
        archivable.append(item)

    return _dedupe_nested(archivable), sorted(set(protected), key=lambda p: p.as_posix())


def _collect_run_v11_action() -> ArchiveAction | None:
    run_v11 = DATA_DIR / "raw/run_v11"
    if not run_v11.exists():
        return None
    return ArchiveAction(
        label="Archive full data/raw/run_v11",
        archive_path=_unique_archive_path(ARCHIVE_DIR / "run_v11.tar.gz"),
        sources=[run_v11],
        preserved=[],
    )


def _collect_v11_tail_action(pinned: set[Path]) -> ArchiveAction | None:
    if not DATA_DIR.exists():
        return None

    matches: list[Path] = []
    for path in DATA_DIR.rglob("*"):
        if _is_in_archive_dir(path):
            continue
        if path == DATA_DIR / "raw/run_v11":
            continue
        if path.name.startswith("v11_"):
            if _is_pinned(path, pinned):
                continue
            matches.append(path)

    sources = _dedupe_nested(_existing_sources(matches))
    if not sources:
        return None

    return ArchiveAction(
        label="Archive legacy v11_* tails from data/",
        archive_path=_unique_archive_path(ARCHIVE_DIR / "v11_tail.tar.gz"),
        sources=sources,
        preserved=[],
    )


def _json_has_invalid_status(value: object) -> bool:
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, str):
                key = str(k).lower()
                if (
                    v in INVALID_AB_STATUSES
                    and (key == "status" or key == "ab_status" or key.endswith("_status") or key == "measurement_state")
                ):
                    return True
            if _json_has_invalid_status(v):
                return True
        return False
    if isinstance(value, list):
        return any(_json_has_invalid_status(item) for item in value)
    return False


def _collect_invalid_ab_action() -> ArchiveAction | None:
    ab_dir = DATA_DIR / "ab_reports"
    if not ab_dir.exists():
        return None

    matches: list[Path] = []
    for path in sorted(ab_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if _json_has_invalid_status(payload):
            matches.append(path)

    if not matches:
        return None

    return ArchiveAction(
        label="Archive invalid-status AB JSON from data/ab_reports",
        archive_path=_unique_archive_path(ARCHIVE_DIR / "ab_reports_invalid_status.tar.gz"),
        sources=matches,
        preserved=[],
    )


def _is_reports_legacy_run(name: str) -> bool:
    if name in WHITELIST_RUNS:
        return False
    if name in REPORTS_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in REPORTS_PREFIXES)


def _collect_reports_legacy_action() -> ArchiveAction | None:
    reports_root = ROOT / "reports/L1_ops"
    if not reports_root.exists():
        return None

    sources: list[Path] = []
    preserved: list[Path] = []

    for run_dir in sorted(p for p in reports_root.iterdir() if p.is_dir()):
        if not _is_reports_legacy_run(run_dir.name):
            continue
        archivable, protected = _split_archivable_paths(run_dir, _is_canonical_or_protected)
        sources.extend(archivable)
        preserved.extend(protected)

    sources = _dedupe_nested(_existing_sources(sources))
    preserved = sorted(set(preserved), key=lambda p: p.as_posix())

    if not sources:
        return None

    return ArchiveAction(
        label="Archive reports/L1_ops legacy runs outside whitelist (preserve canonical/protected units)",
        archive_path=_unique_archive_path(ARCHIVE_DIR / "reports_l1_ops_legacy.tar.gz"),
        sources=sources,
        preserved=preserved,
    )


def _dir_has_canonical_package(run_dir: Path) -> bool:
    if not run_dir.is_dir():
        return False
    existing = {p.name for p in run_dir.glob("*") if p.is_file()}
    return any(name in existing for name in CANONICAL_BASENAMES)


def _collect_human_index_action() -> ArchiveAction | None:
    l1_dir = ROOT / "human_reports/L1"
    if not l1_dir.exists():
        return None

    indices: list[Path] = []
    for run_dir in sorted(p for p in l1_dir.iterdir() if p.is_dir()):
        if run_dir.name in WHITELIST_RUNS:
            continue
        index_md = run_dir / "index.md"
        if not index_md.exists():
            continue
        if _dir_has_canonical_package(run_dir):
            continue
        indices.append(index_md)

    if not indices:
        return None

    return ArchiveAction(
        label="Archive mass human_reports/L1/*/index.md (exclude whitelist + canonical package)",
        archive_path=_unique_archive_path(ARCHIVE_DIR / "human_l1_index_legacy.tar.gz"),
        sources=indices,
        preserved=[],
    )


def _collect_docs_nonpriority_action() -> ArchiveAction | None:
    docs_root = ROOT / "docs"
    docs_archive = docs_root / "archive"
    if not docs_root.exists():
        return None

    candidates: list[Path] = []
    preserved: list[Path] = []

    for entry in sorted(docs_root.iterdir(), key=lambda p: p.as_posix()):
        if entry == docs_archive:
            preserved.append(entry)
            continue
        if entry.is_file():
            if entry.name in ACTIVE_DOCS_P0 or _is_canonical_or_protected(entry):
                preserved.append(entry)
                continue
            candidates.append(entry)
            continue
        if entry.is_dir():
            # Leave only P0 docs and archive directory in active docs root.
            candidates.append(entry)

    candidates = _dedupe_nested(_existing_sources(candidates))
    if not candidates:
        return None

    return ArchiveAction(
        label="Archive non-priority docs to docs/archive (keep P0 active docs + canonical)",
        archive_path=_unique_archive_path(docs_archive / "docs_nonpriority.tar.gz"),
        sources=candidates,
        preserved=sorted(set(preserved), key=lambda p: p.as_posix()),
    )


def _iter_archive_members(action: ArchiveAction) -> list[str]:
    return [src.relative_to(ROOT).as_posix() for src in action.sources]


def _print_dry_run(actions: list[ArchiveAction], pinned: set[Path]) -> None:
    print("=== STEP 2 ARCHIVE PLAN (DRY-RUN) ===")
    if not actions:
        print("Nothing to archive for Step 2.")
        return

    if pinned:
        print("Pinned paths (excluded from v11 tail):")
        for p in sorted(pinned):
            try:
                rel = p.relative_to(ROOT).as_posix()
            except ValueError:
                rel = str(p)
            print(f"- {rel}")
        print("")

    total_sources = 0
    for idx, action in enumerate(actions, start=1):
        print(f"{idx}. {action.label}")
        print(f"   archive -> {action.archive_path.relative_to(ROOT).as_posix()}")
        members = _iter_archive_members(action)
        print(f"   sources -> {len(members)}")
        for m in members:
            print(f"      - {m}")
        if action.preserved:
            print(f"   preserved -> {len(action.preserved)}")
            for p in action.preserved:
                print(f"      - {p.relative_to(ROOT).as_posix()}")
        total_sources += len(members)

    print(f"\nPlanned archive files: {len(actions)}")
    print(f"Planned source entries: {total_sources}")


def _remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    for child in sorted(path.rglob("*"), key=lambda p: (len(p.parts), p.as_posix()), reverse=True):
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
    path.rmdir()


def _create_archive(action: ArchiveAction) -> None:
    action.archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(action.archive_path, "w:gz") as tf:
        for src in action.sources:
            tf.add(src, arcname=src.relative_to(ROOT))

    with tarfile.open(action.archive_path, "r:gz") as tf:
        names = tf.getnames()
    if not names:
        raise RuntimeError(f"Archive is empty: {action.archive_path}")

    for src in action.sources:
        rel = src.relative_to(ROOT).as_posix()
        if not any(name == rel or name.startswith(f"{rel}/") for name in names):
            raise RuntimeError(f"Archive verification failed for source: {rel}")


def _execute(actions: list[ArchiveAction]) -> None:
    for action in actions:
        _create_archive(action)
        for src in sorted(action.sources, key=lambda p: (len(p.parts), p.as_posix()), reverse=True):
            if not src.exists():
                continue
            _remove_tree(src)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Step 2 archival script (safe dry-run + confirm).")
    parser.add_argument(
        "--pinned",
        action="append",
        default=[],
        help="Path (relative to repo root or absolute) to exclude from v11 tail archiving; can be repeated.",
    )
    return parser.parse_args()


def _resolve_pinned(raw_items: list[str]) -> set[Path]:
    pinned: set[Path] = set()
    for item in raw_items:
        raw = Path(item)
        resolved = (ROOT / raw).resolve() if not raw.is_absolute() else raw.resolve()
        pinned.add(resolved)
    return pinned


def main() -> int:
    args = _parse_args()
    pinned = _resolve_pinned(args.pinned)

    actions = [
        x
        for x in (
            _collect_run_v11_action(),
            _collect_v11_tail_action(pinned),
            _collect_invalid_ab_action(),
            _collect_reports_legacy_action(),
            _collect_human_index_action(),
            _collect_docs_nonpriority_action(),
        )
        if x is not None
    ]

    _print_dry_run(actions, pinned)
    if not actions:
        return 0

    answer = input("\nProceed with archiving? (y/n): ").strip().lower()
    if answer != "y":
        print("Aborted. No files were archived.")
        return 0

    _execute(actions)
    print("Step 2 archiving completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
