#!/usr/bin/env python3
"""Focused regressions for m2shell scheduler/signal unit isolation.

Foreign mishe units must never arm, pair with, or incriminate this plant. An
overdue next-due target with its own armed retry timer remains GREEN.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
NOW = 1_794_123_000.0
LOCAL_HEX = "aaaa11111111"
FOREIGN_HEX = "bbbb22222222"
LOCAL_TIMER = f"m2shell-next-due-{LOCAL_HEX}.timer"
FOREIGN_TIMER = f"mishe-next-due-{FOREIGN_HEX}.timer"


def load_check(name: str):
    path = ROOT / "checks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"m2shell_{name.replace('-', '_')}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


armed = load_check("next-due-armed")
churn = load_check("next-due-churn")
coverage = load_check("signal-coverage")
overdue = load_check("overdue-intention")


def completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def listed_timers(home: Path, journal: str) -> tuple[int, list[str]]:
    with mock.patch.object(armed.subprocess, "run", return_value=completed(journal)):
        return armed.list_timers(home)


def armed_home(root: Path, due: float) -> Path:
    (root / "next-due.json").write_text(json.dumps({"at": due}), encoding="utf-8")
    (root / "units-installed").write_text("installed\n", encoding="utf-8")
    return root


class SchedulerNamespaceTests(unittest.TestCase):
    def test_armed_accepts_m2shell_and_ignores_foreign_mishe_timers(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            code, timers = listed_timers(
                home,
                f"Thu 2026 {LOCAL_TIMER} m2shell-next-due-{LOCAL_HEX}.service\n"
                f"Thu 2026 {FOREIGN_TIMER} mishe-next-due-{FOREIGN_HEX}.service\n")
            self.assertEqual(code, 0)
            self.assertEqual(timers, [LOCAL_TIMER])

            code, timers = listed_timers(
                home,
                f"Thu 2026 {FOREIGN_TIMER} mishe-next-due-{FOREIGN_HEX}.service\n")
            self.assertEqual(code, 0)
            self.assertEqual(timers, [])

    def test_overdue_retry_is_green_only_with_m2shell_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = armed_home(Path(tmp), NOW - 3600)
            code, lines = armed.evaluate(home, NOW, [LOCAL_TIMER])
            self.assertEqual(code, 0, lines)
            self.assertIn(LOCAL_TIMER, lines[0])

            code, lines = armed.evaluate(home, NOW, [])
            self.assertEqual(code, 2, lines)
            self.assertTrue(any("never armed" in line for line in lines))

    def test_churn_pairs_only_m2shell_timer_and_service_units(self):
        journal = "\n".join([
            f"Started {LOCAL_TIMER} - next-due timer.",
            f"Starting m2shell-next-due-{LOCAL_HEX}.service - due handler.",
            f"Finished m2shell-next-due-{LOCAL_HEX}.service - due handler.",
            f"Started {FOREIGN_TIMER} - foreign timer.",
            f"Starting mishe-next-due-{FOREIGN_HEX}.service - foreign due handler.",
            f"Finished mishe-next-due-{FOREIGN_HEX}.service - foreign due handler.",
            "Started mishe-producer-next-due-armed.service - foreign producer.",
        ])
        timers, services = churn.units_started(journal)
        self.assertEqual(timers, {LOCAL_HEX})
        self.assertEqual(services, {LOCAL_HEX})
        code, lines = churn.evaluate(timers, services, window_s=300)
        self.assertEqual(code, 0, lines)

        foreign_timers, foreign_services = churn.units_started(
            f"Started {FOREIGN_TIMER} - foreign timer.\n"
            f"Finished mishe-next-due-{FOREIGN_HEX}.service - foreign due handler.\n")
        self.assertEqual(foreign_timers, set())
        self.assertEqual(foreign_services, set())

    def test_coverage_reports_only_failed_m2shell_producers(self):
        stdout = "\n".join([
            "m2shell-producer-signal-a.service loaded failed failed local",
            "mishe-producer-signal-b.service loaded failed failed foreign",
            "m2shell-wake-operator.service loaded failed failed not-a-producer",
        ])
        with mock.patch.object(coverage.subprocess, "run", return_value=completed(stdout)):
            units, note = coverage._failing_units(NOW)
        self.assertIsNone(note)
        self.assertEqual(units, ["m2shell-producer-signal-a.service"])

    def test_overdue_intention_matches_the_scheduler_free_route_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "engine").mkdir()
            # Static route configuration alone does not admit spontaneous work.
            (home / "engine" / "routes.json").write_text(json.dumps({"roles": {
                "free-role": [{"engine": "omp", "free": True}],
            }}), encoding="utf-8")
            state, _, _ = overdue._budget_state(home, "free-role", NOW)
            self.assertEqual(state, "RED")
            fresh = {"free": True, "in_routes": True, "verdict": "FREE", "observed_at": NOW - 60}
            (home / "engine" / "budget.json").write_text(json.dumps({
                "free_models": {"hy4": fresh}}), encoding="utf-8")
            self.assertEqual(overdue._budget_state(home, "free-role", NOW),
                             ("OK", "GREEN", "fresh free route in engine/budget.json"))
            fresh["observed_at"] = NOW - 3601
            (home / "engine" / "budget.json").write_text(json.dumps({
                "free_models": {"hy4": fresh}}), encoding="utf-8")
            state, _, _ = overdue._budget_state(home, "free-role", NOW)
            self.assertEqual(state, "RED")
            (home / "intentions" / "free-role").mkdir(parents=True)
            (home / "intentions" / "free-role" / "idle-initiative.json").write_text(json.dumps({
                "id": "idle-initiative", "due": NOW - 1000, "spontaneous": True}), encoding="utf-8")
            (home / "wake-start-ledger.json").write_text("{}", encoding="utf-8")
            code, lines = overdue.evaluate(home, NOW)
            self.assertEqual(code, 0, lines)
            self.assertTrue(lines[0].startswith("HELD:"), lines)


if __name__ == "__main__":
    unittest.main()
