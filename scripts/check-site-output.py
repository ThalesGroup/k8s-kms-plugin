#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

"""Verify a built Hugo site: local references resolve and in-page anchors exist.

    python3 scripts/check-site-output.py [website/public] [--base-path /k8s-kms-plugin/]

`hugo` exiting 0 says nothing about whether the pages it wrote actually work. This checks the
things that silently do not:

  missing asset   a stylesheet, script or image the HTML references but that is not in the output
  doubled base    a URL carrying the baseURL path twice, e.g. /k8s-kms-plugin/k8s-kms-plugin/css/…
  dead anchor     an in-page #fragment matching no element id on that page

The doubled-base check exists because that failure actually shipped. `relativeURLs = true` looks
like it makes the output more portable, but under a subpath baseURL Hugo emits a relative prefix
back to the site root *and* keeps the path component of baseURL, so every asset URL contained the
subpath twice. The build reported no error, the deploy succeeded, and the published site had no CSS
and no working navigation.

The base path is inferred from the canonical URL Hugo emits, so the check works for whatever
repository built the site; pass --base-path to override.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

# href/src values, tolerating the unquoted attributes `hugo --minify` produces.
REF = re.compile(r'(?:href|src)=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')
ID = re.compile(r'\bid=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')
CANONICAL = re.compile(r'<link[^>]+rel=["\']?canonical["\']?[^>]*>', re.I)
SKIP_PREFIXES = ("http://", "https://", "//", "mailto:", "tel:", "data:", "javascript:")


def attr_value(match: tuple[str, str, str]) -> str:
    return next((g for g in match if g), "")


def infer_base_path(root: Path) -> str:
    """Read the baseURL path component out of the home page's canonical link."""
    index = root / "index.html"
    if not index.exists():
        return "/"
    if m := CANONICAL.search(index.read_text(encoding="utf-8")):
        if href := REF.search(m.group(0)):
            path = urlparse(attr_value(href.groups())).path
            if path:
                return path if path.endswith("/") else path + "/"
    return "/"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default="website/public", type=Path)
    ap.add_argument("--base-path", help="baseURL path component, e.g. /k8s-kms-plugin/ (inferred by default)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root: Path = args.root
    if not root.is_dir():
        print(f"check-site-output: {root} is not a directory — run the site build first", file=sys.stderr)
        return 1

    base = args.base_path or infer_base_path(root)
    if not base.startswith("/"):
        base = "/" + base
    if not base.endswith("/"):
        base += "/"
    segment = base.strip("/")

    pages = sorted(root.rglob("*.html"))
    if not pages:
        print(f"check-site-output: no HTML found under {root}", file=sys.stderr)
        return 1

    problems: list[str] = []
    checked_refs = checked_anchors = 0

    for page in pages:
        html = page.read_text(encoding="utf-8")
        where = page.relative_to(root)
        ids = {attr_value(m) for m in ID.findall(html)}

        for raw in (attr_value(m) for m in REF.findall(html)):
            url = raw.strip()
            if not url or url.startswith(SKIP_PREFIXES) or url == "#":
                continue

            # In-page fragment.
            if url.startswith("#"):
                checked_anchors += 1
                if unquote(url[1:]) not in ids:
                    problems.append(f"{where}: dead anchor -> {url}")
                continue

            path_part = unquote(urlparse(url).path)
            if not path_part:
                continue
            checked_refs += 1

            # The failure that shipped: baseURL's path applied twice.
            if segment and f"/{segment}/{segment}/" in path_part + "/":
                problems.append(f"{where}: baseURL applied twice -> {url}")
                continue

            if path_part.startswith("/"):
                if segment and not path_part.startswith(base):
                    problems.append(f"{where}: absolute path missing the {base} prefix -> {url}")
                    continue
                target = root / path_part[len(base):]
            else:
                target = (page.parent / path_part).resolve()

            # A directory URL is served by its index.html.
            if target.is_dir():
                target = target / "index.html"
            if not target.exists():
                problems.append(f"{where}: missing target -> {url}")

    if problems:
        print(f"check-site-output: {len(problems)} problem(s) in {len(pages)} pages:\n", file=sys.stderr)
        for p in problems[:60]:
            print(f"  {p}", file=sys.stderr)
        if len(problems) > 60:
            print(f"  … and {len(problems) - 60} more", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"check-site-output: {len(pages)} pages, {checked_refs} local references and "
              f"{checked_anchors} anchors all resolve (base {base})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
