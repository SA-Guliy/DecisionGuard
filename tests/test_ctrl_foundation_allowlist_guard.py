from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts import run_all as run_all_mod


class CtrlFoundationAllowlistGuardTests(unittest.TestCase):
    def test_forbidden_step_fails_closed(self) -> None:
        prev_active = run_all_mod._CTRL_FOUNDATION_ACTIVE
        prev_steps = list(run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS)
        run_all_mod._CTRL_FOUNDATION_ACTIVE = True
        run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS = []
        try:
            with self.assertRaises(SystemExit):
                run_all_mod._run_step(
                    ["python3", "-c", "print('x')"],
                    "run_commander_priority",
                    Path("data/logs/ut_ctrl_foundation_guard.log"),
                )
        finally:
            run_all_mod._CTRL_FOUNDATION_ACTIVE = prev_active
            run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS = prev_steps

    def test_allowed_step_is_recorded(self) -> None:
        prev_active = run_all_mod._CTRL_FOUNDATION_ACTIVE
        prev_steps = list(run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS)
        run_all_mod._CTRL_FOUNDATION_ACTIVE = True
        run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS = []
        fake_result = subprocess.CompletedProcess(args=["python3"], returncode=0, stdout="", stderr="")
        try:
            with (
                mock.patch.object(run_all_mod.subprocess, "run", return_value=fake_result),
                mock.patch.object(run_all_mod, "_append_step_log", return_value=None),
                mock.patch.object(run_all_mod, "_print_verbose_tail", return_value=None),
            ):
                run_all_mod._run_step(
                    ["python3", "-c", "print('ok')"],
                    "run_dq",
                    Path("data/logs/ut_ctrl_foundation_guard_ok.log"),
                )
            self.assertEqual(run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS, ["run_dq"])
        finally:
            run_all_mod._CTRL_FOUNDATION_ACTIVE = prev_active
            run_all_mod._CTRL_FOUNDATION_EXECUTED_STEPS = prev_steps


if __name__ == "__main__":
    unittest.main()

