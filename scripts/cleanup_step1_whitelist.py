#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

WHITELIST_RUNS = ("v13_agent_prod_013", "v13_agent_prod_011")
DELETE_RUNS = ("v13_agent_prod_001", "v13_agent_prod_010", "v13_agent_prod_012")
STATUS_FLAGS = ("MISSING_ASSIGNMENT", "UNOBSERVABLE", "INVALID_METHODS")

CANONICAL_BASENAMES = {
    "канонический_стандарт.md",
    "AB_stat_report_standart.md",
    "Decision Card_standard.md",
    "AB_STAT_REPORT_CANONICAL.md",
    "DECISION_CARD_CANONICAL.md",
    "STANDARD_CONFORMANCE.md",
}

PROTECTED_EXACT = {
    ROOT / "reports/L1_ops/v13_agent_prod_013/AB_STAT_REPORT.md",
    ROOT / "reports/L1_ops/v13_agent_prod_013/decision_card.md",
    ROOT / "reports/L1_ops/v13_agent_prod_011/AB_STAT_REPORT.md",
    ROOT / "reports/L1_ops/v13_agent_prod_011/decision_card.md",
}

SAFE_TOKEN_CHARS = r"A-Za-z0-9"
DELETE_RUN_RE = re.compile(
    rf"(?<![{SAFE_TOKEN_CHARS}])(?:{'|'.join(re.escape(x) for x in DELETE_RUNS)})(?![{SAFE_TOKEN_CHARS}])"
)
WHITELIST_RUN_RE = re.compile(
    rf"(?<![{SAFE_TOKEN_CHARS}])(?:{'|'.join(re.escape(x) for x in WHITELIST_RUNS)})(?![{SAFE_TOKEN_CHARS}])"
)
PROTECTED_EXACT_RESOLVED = {p.resolve() for p in PROTECTED_EXACT}


def _path_in_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False


def _is_whitelist_path(path: Path) -> bool:
    return any(part in WHITELIST_RUNS for part in path.parts)


def _is_protected(path: Path) -> bool:
    if _is_whitelist_path(path):
        return True
    rel = path.relative_to(ROOT).as_posix() if _path_in_repo(path) else path.as_posix()
    if WHITELIST_RUN_RE.search(rel):
        return True
    if path.name in CANONICAL_BASENAMES:
        return True
    upper_name = path.name.upper()
    if "CANONICAL" in upper_name or "PROTECTED" in upper_name:
        return True
    resolved = path.resolve()
    if resolved in PROTECTED_EXACT_RESOLVED:
        return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _add_candidate(
    candidates: dict[Path, list[str]],
    path: Path,
    reason: str,
) -> None:
    if not path.exists():
        return
    if not _path_in_repo(path):
        return
    if _is_protected(path):
        return
    candidates[path].append(reason)


def _collect_raw_candidates() -> tuple[dict[Path, list[str]], set[Path]]:
    candidates: dict[Path, list[str]] = defaultdict(list)
    architect_delete_roots: set[Path] = set()

    _add_candidate(candidates, ROOT / "data/.DS_Store", "trash/cache: data/.DS_Store")
    _add_candidate(candidates, ROOT / "fontlist-v390.json", "trash/cache: fontlist-v390.json")
    run_summaries = ROOT / "data/run_summaries"
    if run_summaries.exists() and run_summaries.is_dir() and not any(run_summaries.iterdir()):
        _add_candidate(candidates, run_summaries, "trash/cache: empty data/run_summaries")

    for run in DELETE_RUNS:
        rep = ROOT / f"reports/L1_ops/{run}"
        hum = ROOT / f"human_reports/L1/{run}"
        _add_candidate(candidates, rep, f"bad early prod run: {run}")
        _add_candidate(candidates, hum, f"mirror bad early prod run: {run}")
        if rep.exists():
            architect_delete_roots.add(rep)
        if hum.exists():
            architect_delete_roots.add(hum)

    data_root = ROOT / "data"
    if data_root.exists():
        for path in data_root.rglob("*"):
            rel = path.relative_to(data_root).as_posix()
            if DELETE_RUN_RE.search(rel):
                _add_candidate(candidates, path, "data artifact tied to delete run (001/010/012)")

    for root_name in ("reports", "human_reports"):
        base = ROOT / root_name
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.name not in {"AB_STAT_REPORT.md", "decision_card.md"}:
                continue
            if "/archive/" in path.as_posix():
                continue
            if _is_protected(path):
                continue
            text = _read_text(path)
            if any(flag in text for flag in STATUS_FLAGS):
                _add_candidate(
                    candidates,
                    path,
                    "status in {MISSING_ASSIGNMENT, UNOBSERVABLE, INVALID_METHODS}",
                )

    legacy_token = "doctor_science_rules_v2"
    reports_ops = ROOT / "reports/L1_ops"
    if reports_ops.exists():
        for run_dir in reports_ops.iterdir():
            if not run_dir.is_dir():
                continue
            if run_dir.name in WHITELIST_RUNS:
                continue
            evidence_pack = run_dir / "evidence_pack.json"
            if not evidence_pack.exists():
                continue
            has_canonical = any(
                (run_dir / name).exists()
                for name in (
                    "AB_STAT_REPORT_CANONICAL.md",
                    "DECISION_CARD_CANONICAL.md",
                    "STANDARD_CONFORMANCE.md",
                )
            )
            if legacy_token in _read_text(evidence_pack) and not has_canonical:
                _add_candidate(
                    candidates,
                    run_dir,
                    "legacy doctor_science_rules_v2 run without canonical structure",
                )

    if data_root.exists():
        for path in data_root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".json", ".md", ".txt"}:
                continue
            if _is_whitelist_path(path):
                continue
            rel = path.relative_to(ROOT).as_posix()
            if WHITELIST_RUN_RE.search(rel):
                continue
            lower_name = path.name.lower()
            if not any(token in lower_name for token in ("doctor", "variance", "evidence_pack")):
                continue
            if legacy_token in _read_text(path):
                _add_candidate(
                    candidates,
                    path,
                    "legacy doctor_science_rules_v2 artifact outside whitelist",
                )

    return candidates, architect_delete_roots


def _analyze_directory(
    dir_path: Path,
) -> tuple[list[Path], list[Path]]:
    descendants = sorted(dir_path.rglob("*"), key=lambda p: (len(p.parts), p.as_posix()))
    protected: list[Path] = []
    blocked_dirs: set[Path] = set()

    for item in descendants:
        if _is_protected(item):
            protected.append(item)
            for parent in item.parents:
                if parent == dir_path.parent:
                    break
                blocked_dirs.add(parent)

    if not protected and not _is_protected(dir_path):
        return [dir_path], []

    deletable: list[Path] = []
    for item in descendants:
        if _is_protected(item):
            continue
        if item.is_dir() and item in blocked_dirs:
            continue
        deletable.append(item)

    return deletable, protected


def _build_delete_plan(
    raw_candidates: dict[Path, list[str]],
) -> tuple[dict[Path, list[str]], dict[Path, list[Path]]]:
    actions: dict[Path, list[str]] = defaultdict(list)
    collisions: dict[Path, list[Path]] = {}

    for candidate, reasons in sorted(raw_candidates.items(), key=lambda x: (len(x[0].parts), x[0].as_posix())):
        if not candidate.exists() or _is_protected(candidate):
            continue
        if candidate.is_dir() and not candidate.is_symlink():
            deletable, protected = _analyze_directory(candidate)
            if protected:
                collisions[candidate] = protected
            for item in deletable:
                if not item.exists() or _is_protected(item):
                    continue
                actions[item].extend(reasons)
                if protected:
                    actions[item].append("split-delete: parent has protected descendants")
        else:
            actions[candidate].extend(reasons)

    pruned: dict[Path, list[str]] = {}
    deleted_dirs: list[Path] = []
    for path in sorted(actions.keys(), key=lambda p: (len(p.parts), p.as_posix())):
        if any(parent in path.parents for parent in deleted_dirs):
            continue
        pruned[path] = sorted(set(actions[path]))
        if path.is_dir():
            deleted_dirs.append(path)

    return pruned, collisions


def _print_plan(actions: dict[Path, list[str]]) -> None:
    print("=== STEP 1 DELETE PLAN (DRY-RUN) ===")
    if not actions:
        print("No deletion candidates found for Step 1.")
        return

    for idx, path in enumerate(sorted(actions.keys(), key=lambda p: p.as_posix()), start=1):
        rel = path.relative_to(ROOT).as_posix()
        kind = "DIR " if path.is_dir() else "FILE"
        reason = "; ".join(actions[path])
        print(f"{idx:04d}. [{kind}] {rel}")
        print(f"      reason: {reason}")

    print(f"\nTotal candidates: {len(actions)}")


def _print_collisions(collisions: dict[Path, list[Path]]) -> None:
    print("\n=== PROTECTED COLLISION ===")
    if not collisions:
        print("No protected collisions detected.")
        return
    for root in sorted(collisions.keys(), key=lambda p: p.as_posix()):
        root_rel = root.relative_to(ROOT).as_posix()
        print(f"- candidate dir: {root_rel}")
        for protected in sorted(collisions[root], key=lambda p: p.as_posix()):
            p_rel = protected.relative_to(ROOT).as_posix()
            print(f"  protected: {p_rel}")


def _delete_directory_checked(path: Path) -> tuple[int, str | None]:
    if not path.exists():
        return 0, None
    protected = [p for p in path.rglob("*") if _is_protected(p)]
    if protected:
        return 0, f"protected descendants found ({len(protected)})"

    deleted = 0
    for item in sorted(path.rglob("*"), key=lambda p: (len(p.parts), p.as_posix()), reverse=True):
        try:
            if item.is_symlink() or item.is_file():
                item.unlink()
            elif item.is_dir():
                item.rmdir()
            deleted += 1
        except OSError as exc:
            return deleted, str(exc)
    try:
        path.rmdir()
        deleted += 1
    except OSError as exc:
        return deleted, str(exc)
    return deleted, None


def _execute_delete(actions: dict[Path, list[str]]) -> tuple[int, list[tuple[Path, str]]]:
    deleted = 0
    errors: list[tuple[Path, str]] = []

    for path in sorted(actions.keys(), key=lambda p: (len(p.parts), p.as_posix()), reverse=True):
        if not path.exists():
            continue
        if _is_protected(path):
            errors.append((path, "path became protected"))
            continue
        if path.is_dir() and not path.is_symlink():
            count, err = _delete_directory_checked(path)
            deleted += count
            if err:
                errors.append((path, err))
            continue
        try:
            path.unlink()
            deleted += 1
        except OSError as exc:
            errors.append((path, str(exc)))

    return deleted, errors


def main() -> int:
    raw_candidates, architect_delete_roots = _collect_raw_candidates()
    actions, collisions = _build_delete_plan(raw_candidates)

    _print_plan(actions)
    _print_collisions(collisions)

    blocking_collisions = {
        root: paths
        for root, paths in collisions.items()
        if root in architect_delete_roots
    }
    if blocking_collisions:
        print(
            "\nFATAL: protected collision detected in architect-mandated delete directories. "
            "Cleanup stopped."
        )
        return 2

    if not actions:
        return 0

    answer = input("\nProceed? (y/n): ").strip().lower()
    if answer != "y":
        print("Aborted. No files were deleted.")
        return 0

    deleted, errors = _execute_delete(actions)
    print(f"Deleted entries: {deleted}")
    if errors:
        print(f"Errors: {len(errors)}")
        for path, err in errors:
            rel = path.relative_to(ROOT).as_posix() if _path_in_repo(path) else str(path)
            print(f"- {rel}: {err}")
        return 1

    print("Step 1 deletion completed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
