"""Block commits that would publish a secret or a confidential name.

    python scripts/precommit_scan.py              # the staged files (what a commit would add)
    python scripts/precommit_scan.py --all        # every tracked file (CI)
    python scripts/precommit_scan.py --install    # run it as the git pre-commit hook

Secrets: every value of a KEY / SECRET / TOKEN / PASSWORD setting in .env (12+ characters). Confidential names: a
regular expression read from SOC_BANNED_NAMES_REGEX or .git/info/banned-names - kept outside the repository, so the
names themselves are never committed. Findings name the file and the reason, never the value. Exit code 1 on any.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_KEYS = ("KEY", "SECRET", "TOKEN", "PASSWORD")


def secret_values(env_file: Path) -> list[str]:
    if not env_file.is_file():
        return []
    vals = []
    for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            v = v.split(" #")[0].strip().strip('"').strip("'")
            if any(s in k.upper() for s in SECRET_KEYS) and len(v) >= 12:
                vals.append(v)
    return vals


def banned_pattern() -> str | None:
    if os.environ.get("SOC_BANNED_NAMES_REGEX"):
        return os.environ["SOC_BANNED_NAMES_REGEX"]
    f = ROOT / ".git" / "info" / "banned-names"
    return f.read_text(encoding="utf-8").strip() or None if f.is_file() else None


def scan(paths: list[Path], *, env_file: Path, banned: str | None) -> list[tuple[str, str]]:
    secrets = secret_values(env_file)
    rx = re.compile(banned) if banned else None
    findings = []
    for p in paths:
        if not p.is_file() or p.resolve() == env_file.resolve():
            continue
        raw = p.read_bytes()
        if b"\0" in raw[:8192]:
            continue                    # binary (images, models): random bytes spell short words, like git grep -I skips
        text = raw.decode("utf-8", errors="ignore")
        if any(v in text for v in secrets):
            findings.append((str(p), "secret value from .env"))
        if rx is not None and rx.search(text):
            findings.append((str(p), "confidential name"))
    return findings


def _files(all_tracked: bool) -> list[Path]:
    cmd = ["git", "ls-files"] if all_tracked else ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout  # nosec B603 - fixed argv
    return [ROOT / f for f in out.splitlines() if f]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--install", action="store_true")
    a = ap.parse_args(argv)
    if a.install:
        hook = ROOT / ".git" / "hooks" / "pre-commit"
        hook.write_text('#!/bin/sh\nexec python "$(git rev-parse --show-toplevel)/scripts/precommit_scan.py"\n',
                        encoding="utf-8")
        hook.chmod(0o755)
        print(f"installed {hook}")
        return 0
    banned = banned_pattern()
    if banned is None:
        print("note: no confidential-name pattern (set SOC_BANNED_NAMES_REGEX or .git/info/banned-names)")
    findings = scan(_files(a.all), env_file=ROOT / ".env", banned=banned)
    for f, why in findings:
        print(f"BLOCKED {f}: {why}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
