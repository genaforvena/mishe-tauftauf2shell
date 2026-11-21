#!/usr/bin/env python3
"""Exercise autonomous publication entirely in temporary repos with file remotes.

The plant checkout is used only to load the script under test. No command runs
against it, no network remote is used, and every test gets a fresh work repo
and bare origin. Reconciliation must preserve both parents and the exact local
tree while leaving a dirty index and worktree byte-for-byte untouched.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("main_publication", ROOT / "checks" / "main-publication.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load checks/main-publication.py")
pub = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pub)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Publication Test",
        "GIT_AUTHOR_EMAIL": "publication@example.invalid",
        "GIT_COMMITTER_NAME": "Publication Test",
        "GIT_COMMITTER_EMAIL": "publication@example.invalid",
    }
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=False, env=env)
    if check and done.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed ({done.returncode}): {done.stderr}{done.stdout}")
    return done


def out(repo: Path, *args: str) -> str:
    return git(repo, *args).stdout.strip()


class PublicationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.remote = self.root / "remote.git"
        self.work = self.root / "work"
        git(self.root, "init", "--quiet", "--bare", "--initial-branch=main", str(self.remote))
        git(self.root, "init", "--quiet", "--initial-branch=main", str(self.work))
        git(self.work, "config", "user.name", "Publication Test")
        git(self.work, "config", "user.email", "publication@example.invalid")
        git(self.work, "remote", "add", "origin", str(self.remote))
        (self.work / "base.txt").write_text("base\n", encoding="utf-8")
        git(self.work, "add", "base.txt")
        git(self.work, "commit", "--quiet", "-m", "base")
        git(self.work, "push", "--quiet", "origin", "main")
        self.base = out(self.work, "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def commit(self, repo: Path, name: str) -> str:
        (repo / name).write_text(f"{name}\n", encoding="utf-8")
        git(repo, "add", name)
        git(repo, "commit", "--quiet", "-m", name)
        return out(repo, "rev-parse", "HEAD")

    def other_clone(self) -> Path:
        other = self.root / "other"
        git(self.root, "clone", "--quiet", str(self.remote), str(other))
        git(other, "checkout", "--quiet", "-B", "main", "origin/main")
        git(other, "config", "user.name", "Other Publisher")
        git(other, "config", "user.email", "other@example.invalid")
        return other

    def diverge(self) -> tuple[str, str]:
        other = self.other_clone()
        self.commit(other, "theirs.txt")
        git(other, "push", "--quiet", "origin", "main")
        theirs = out(self.remote, "rev-parse", "refs/heads/main")
        mine = self.commit(self.work, "mine.txt")
        return mine, theirs

    def worktree_bytes(self) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        for path in self.work.rglob("*"):
            relative = path.relative_to(self.work)
            if path.is_file() and ".git" not in relative.parts:
                files[str(relative)] = path.read_bytes()
        return files

    def assert_both_histories(self, reconciled: str, mine: str, theirs: str) -> None:
        parents = out(self.work, "rev-list", "--parents", "-n", "1", reconciled).split()[1:]
        self.assertEqual(parents, [theirs, mine])
        self.assertEqual(git(self.work, "merge-base", "--is-ancestor", theirs, reconciled).returncode, 0)
        self.assertEqual(git(self.work, "merge-base", "--is-ancestor", mine, reconciled).returncode, 0)

    def test_strict_fast_forward_then_already_published(self) -> None:
        mine = self.commit(self.work, "local.txt")

        code, lines = pub.publish(self.work)

        self.assertEqual(code, 0, lines)
        self.assertIn("pushed 1 unpushed commit", lines[0])
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), mine)
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), mine)
        code, lines = pub.publish(self.work)
        self.assertEqual(code, 0, lines)
        self.assertIn("already holds HEAD", lines[0])
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), mine)

    def test_divergence_reconciles_tree_parents_and_dirty_checkout(self) -> None:
        mine, theirs = self.diverge()
        local_tree = out(self.work, "rev-parse", f"{mine}^{{tree}}")
        (self.work / "base.txt").write_text("unstaged worktree edit\n", encoding="utf-8")
        (self.work / "staged.txt").write_text("staged but uncommitted\n", encoding="utf-8")
        git(self.work, "add", "staged.txt")
        (self.work / "lab-output").mkdir()
        (self.work / "lab-output" / "untracked.bin").write_bytes(b"\x00dirty lab output\xff")
        index_before = (self.work / ".git" / "index").read_bytes()
        worktree_before = self.worktree_bytes()

        real_git = pub.git
        commands: list[tuple[str, ...]] = []

        def recording_git(repo: Path, *args: str, **kwargs: object) -> tuple[int, str]:
            commands.append(args)
            return real_git(repo, *args, **kwargs)

        pub.git = recording_git
        try:
            code, lines = pub.publish(self.work)
        finally:
            pub.git = real_git

        self.assertEqual(code, 0, lines)
        self.assertIn("reconciled remote", lines[0])
        reconciled = out(self.work, "rev-parse", "HEAD")
        self.assertNotIn(reconciled, (mine, theirs))
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), reconciled)
        self.assertEqual(out(self.work, "rev-parse", f"{reconciled}^{{tree}}"), local_tree)
        self.assertEqual(git(self.work, "diff", "--exit-code", mine, reconciled).returncode, 0)
        self.assert_both_histories(reconciled, mine, theirs)
        self.assertEqual((self.work / ".git" / "index").read_bytes(), index_before)
        self.assertEqual(self.worktree_bytes(), worktree_before)

        updates = [args for args in commands if args[0] == "update-ref"]
        self.assertEqual(updates, [("update-ref", "refs/heads/main", reconciled, mine)])
        pushes = [args for args in commands if args[0] == "push"]
        self.assertEqual(len(pushes), 1)
        for args in pushes:
            self.assertFalse(any(arg.startswith("--force") for arg in args), args)
            self.assertNotIn("-f", args)
            self.assertFalse(any(arg.startswith("+") for arg in args), args)

    def test_head_race_refuses_ref_update_and_push(self) -> None:
        mine, theirs = self.diverge()
        real_git = pub.git
        commands: list[tuple[str, ...]] = []
        racers: list[str] = []

        def racing_git(repo: Path, *args: str, **kwargs: object) -> tuple[int, str]:
            result = real_git(repo, *args, **kwargs)
            commands.append(args)
            if args[0] == "commit-tree" and result[0] == 0:
                tree = out(self.work, "rev-parse", f"{mine}^{{tree}}")
                racer = out(self.work, "commit-tree", tree, "-p", mine, "-m", "racing local commit")
                git(self.work, "update-ref", "refs/heads/main", racer, mine)
                racers.append(racer)
            return result

        pub.git = racing_git
        try:
            code, lines = pub.publish(self.work)
        finally:
            pub.git = real_git

        self.assertEqual(code, 2, lines)
        self.assertIn("changed during reconciliation", lines[0])
        self.assertEqual(len(racers), 1)
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), racers[0])
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), theirs)
        self.assertFalse(any(args[0] == "push" for args in commands))
        attempted = [args for args in commands if args[0] == "update-ref"]
        self.assertEqual(len(attempted), 1)
        self.assertEqual(attempted[0][-1], mine)

    def test_failed_reconciliation_push_is_fast_forward_next_tick(self) -> None:
        mine, theirs = self.diverge()
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)

        code, lines = pub.publish(self.work)

        self.assertEqual(code, 2, lines)
        self.assertIn("push", lines[0])
        reconciled = out(self.work, "rev-parse", "HEAD")
        self.assertNotIn(reconciled, (mine, theirs))
        self.assert_both_histories(reconciled, mine, theirs)
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), theirs)
        hook.unlink()

        real_git = pub.git
        second_commands: list[tuple[str, ...]] = []

        def recording_git(repo: Path, *args: str, **kwargs: object) -> tuple[int, str]:
            second_commands.append(args)
            return real_git(repo, *args, **kwargs)

        pub.git = recording_git
        try:
            code, lines = pub.publish(self.work)
        finally:
            pub.git = real_git

        self.assertEqual(code, 0, lines)
        self.assertNotIn("reconciled", lines[0])
        self.assertIn("pushed", lines[0])
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), reconciled)
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), reconciled)
        self.assertFalse(any(args[0] in ("commit-tree", "update-ref") for args in second_commands))
        pushes = [args for args in second_commands if args[0] == "push"]
        self.assertEqual(len(pushes), 1)
        self.assertFalse(any(arg.startswith("--force") or arg == "-f" for args in pushes for arg in args))

    def test_local_behind_is_red_without_changing_either_main(self) -> None:
        other = self.other_clone()
        self.commit(other, "theirs.txt")
        git(other, "push", "--quiet", "origin", "main")
        theirs = out(self.remote, "rev-parse", "refs/heads/main")

        code, lines = pub.publish(self.work)

        self.assertEqual(code, 2, lines)
        self.assertIn("behind", lines[0])
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), self.base)
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), theirs)

    def test_non_main_head_is_a_noop_even_with_an_unreadable_remote(self) -> None:
        git(self.work, "checkout", "--quiet", "-b", "side")
        side = self.commit(self.work, "side.txt")
        git(self.work, "remote", "set-url", "origin", str(self.root / "missing.git"))

        code, lines = pub.publish(self.work)

        self.assertEqual(code, 0, lines)
        self.assertIn("not main", lines[0])
        self.assertEqual(out(self.work, "rev-parse", "HEAD"), side)
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), self.base)

    def test_unknown_remote_is_unknown(self) -> None:
        self.commit(self.work, "local.txt")
        git(self.work, "remote", "set-url", "origin", str(self.root / "missing.git"))

        code, lines = pub.publish(self.work)

        self.assertEqual(code, 3, lines)
        self.assertIn("cannot read origin/main", lines[0])
        self.assertEqual(out(self.remote, "rev-parse", "refs/heads/main"), self.base)


if __name__ == "__main__":
    unittest.main(verbosity=2)
