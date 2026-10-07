#!/usr/bin/env python3
"""Checks that every relative link in the repository's Markdown points at a file or directory of the repository.

    python3 scripts/check-links.py [FILE.md ...]        (make lint; default: every tracked .md file)

Links to the web (http, https, mailto) and to anchors within a page are not followed. The proof of concept's
third-party sources (third_party/*/src*) are not checked. A link out of the repository is broken even if its target
exists on this machine: a fresh clone has nothing beside it. Prints each broken link with its file and line; exits 1
if there is one.
"""

import re
import subprocess
import sys
from pathlib import Path

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
REPO = Path(__file__).resolve().parent.parent


def tracked_markdown():
    out = subprocess.run(["git", "ls-files", "*.md"], cwd=REPO, capture_output=True, text=True, check=True).stdout
    return [REPO / f for f in out.split() if not re.match(r"third_party/[^/]+/src", f)]


def broken(path):
    in_code = False
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        for target in LINK.findall(line):
            if re.match(r"(https?|mailto):", target) or target.startswith("#"):
                continue
            dest = (path.parent / target.split("#", 1)[0]).resolve()
            if dest != REPO and REPO not in dest.parents:
                yield n, f"{target} (out of the repository)"
            elif not dest.exists():
                yield n, target


def main():
    files = [Path(a).resolve() for a in sys.argv[1:]] or tracked_markdown()
    bad = 0
    for f in files:
        for n, target in broken(f):
            print(f"{f.relative_to(REPO)}:{n}: {target}")
            bad += 1
    print(f"{len(files)} files, {bad} broken links")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
