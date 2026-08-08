#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

"""Verify that every relative Markdown link and #anchor in the documentation resolves.

Run it with `make check-doc-links`, or directly:

    python3 scripts/check-doc-links.py [--quiet] [paths...]

Two failure modes are reported:

  missing file   a relative link whose target does not exist on disk
  dead anchor    a #fragment that matches no heading in the target file

Anchors are the ones that rot silently. Manually numbered headings made this worse — the anchors
README.md used for docs/README.md drifted out of sync with the section numbers and pointed at the
wrong sections — and any restructuring of the documentation tree can reintroduce the same class of
breakage without a single broken build.

Only relative links are checked. External http(s) targets are skipped deliberately: reaching the
network would make the check slow, flaky and dependent on third-party uptime.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Repository root, derived from this file's location so the script works from any directory.
REPO = Path(__file__).resolve().parent.parent

# Directories whose Markdown is generated and therefore not hand-maintained. They are still
# *checked*, but they are not walked for extra input paths beyond the defaults below.
DEFAULT_PATHS = [Path("README.md"), Path("CHANGELOG.md"), Path("docs")]

MD_LINK = re.compile(r"\[(?:[^\]]*)\]\(\s*(?P<url>[^)\s]+?)\s*\)")
HEADING = re.compile(r"^#{1,6}\s+(?P<text>.*?)\s*$")
HTML_ANCHOR = re.compile(r'<a\s+(?:id|name)="(?P<id>[^"]+)"')
INLINE_LINK_TEXT = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SKIP_SCHEMES = ("http://", "https://", "mailto:", "tel:", "ftp://")


def github_slug(text: str) -> str:
    """Reproduce GitHub's heading-to-anchor slug.

    GitHub lowercases, drops every character that is not a word character, space or hyphen, then
    turns each remaining space into a hyphen. Emoji and punctuation vanish but the spaces around
    them do not, which is why "Installation 🔧" anchors as "installation-" and "HSM & TPM guides"
    as "hsm--tpm-guides". Collapsing those runs would silently mismatch real anchors in this repo.
    """
    s = INLINE_LINK_TEXT.sub(r"\1", text.strip()).replace("`", "").lower()
    return re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE).replace(" ", "-")


def anchors_of(path: Path) -> set[str]:
    """Every anchor the given Markdown file exposes."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            # A "#" inside a fenced block is a shell comment, not a heading.
            continue

        if m := HEADING.match(line):
            base = github_slug(m.group("text"))
            # GitHub disambiguates repeated headings with -1, -2, ... suffixes.
            n = seen.get(base, 0)
            seen[base] = n + 1
            found.add(base if n == 0 else f"{base}-{n}")

        found.update(HTML_ANCHOR.findall(line))

    return found


def markdown_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for rel in paths:
        p = REPO / rel
        if p.is_dir():
            out.extend(sorted(p.rglob("*.md")))
        elif p.suffix == ".md" and p.exists():
            out.append(p)
    # Deduplicate while keeping a stable order.
    return list(dict.fromkeys(out))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path, default=DEFAULT_PATHS,
                    help="files or directories to check (default: README.md CHANGELOG.md docs/)")
    ap.add_argument("--quiet", action="store_true", help="only print on failure")
    args = ap.parse_args()

    files = markdown_files(args.paths or DEFAULT_PATHS)
    if not files:
        print("check-doc-links: no Markdown files found", file=sys.stderr)
        return 1

    anchor_cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    checked = 0

    for path in files:
        for m in MD_LINK.finditer(path.read_text(encoding="utf-8")):
            url = m.group("url")
            if url.startswith(SKIP_SCHEMES) or url.startswith("#!"):
                continue

            rel, sep, frag = url.partition("#")
            checked += 1
            here = path.relative_to(REPO)

            target = path if rel == "" else (path.parent / rel)
            if rel:
                if not target.exists():
                    problems.append(f"{here}: missing file -> {url}")
                    continue
                if target.is_dir():
                    continue

            if not sep or not frag:
                continue

            target = target.resolve()
            if target.suffix != ".md":
                # Fragments into non-Markdown targets (e.g. a line anchor in a source file) are
                # not resolvable here.
                continue
            if target not in anchor_cache:
                anchor_cache[target] = anchors_of(target)
            if frag not in anchor_cache[target]:
                problems.append(f"{here}: dead anchor -> {url}")

    if problems:
        print(f"check-doc-links: {len(problems)} broken link(s) of {checked} checked:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"check-doc-links: {checked} relative links across {len(files)} files all resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
