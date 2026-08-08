#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT
"""Generate docs/glossary.md from docs/termbase.yaml.

Why two files exist for one glossary
------------------------------------
Hextra renders a glossary from a Hugo *data* file (data/<lang>/termbase.yaml) through its
`glossary` layout, which ignores the page body entirely. GitHub, on the other hand, renders the
body and knows nothing about Hugo data files. Serving both from one source means: the YAML is
authoritative, `layout: glossary` gives the site its styled <dl>, and this script writes the table
GitHub shows. Neither can drift, because CI runs `--check`.

Usage:
    scripts/gen-glossary.py            # write docs/glossary.md
    scripts/gen-glossary.py --check    # exit 1 if the file on disk is not what we would write
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment problem, not a logic error
    sys.exit("gen-glossary: PyYAML is required (pip install pyyaml)")

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE = REPO / "docs" / "termbase.yaml"
TARGET = REPO / "docs" / "glossary.md"

FRONT_MATTER = """---
title: "Glossary"
weight: 95
layout: glossary
---
"""

# Kept deliberately short: on the published site this body is never rendered — Hextra's glossary
# layout draws the <dl> from the data file and drops .Content — so anything written here is for
# GitHub readers only.
PREAMBLE = """<!-- GENERATED FILE — DO NOT EDIT.
     Source: docs/termbase.yaml. Regenerate with `make glossary`.
     The published site renders this page from the same YAML through Hextra's glossary layout;
     the table below is what GitHub shows. -->

Terms used across this documentation. The source is
[`docs/termbase.yaml`](https://github.com/eclipse-keysealer/k8s-kms-plugin/blob/master/docs/termbase.yaml);
this page is generated from it by `make glossary`.

| Term | Definition |
|------|------------|
"""


def sort_key(entry: dict) -> tuple[str, str]:
    """Order entries the way Hugo's `sort` orders them.

    Hugo collates language-aware, which is case-insensitive — so `etcd` lands between
    `Envelope encryption` and `EncryptionConfiguration` rather than after `Trusted Platform
    Module`. Matching that here is what keeps the table's order identical to the site's <dl>.
    """
    term = entry["term"]
    return (term.casefold(), term)


def load_terms() -> list[dict]:
    entries = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        sys.exit(f"gen-glossary: {SOURCE} must hold a non-empty list of terms")

    seen: dict[str, int] = {}
    for i, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            sys.exit(f"gen-glossary: entry {i} is not a mapping")
        for field in ("term", "definition"):
            if not str(entry.get(field, "")).strip():
                sys.exit(f"gen-glossary: entry {i} has no {field}")
        for field in ("term", "abbr", "definition"):
            value = str(entry.get(field, ""))
            # A pipe would split a table cell; a newline would end the row. The theme prints the
            # definition verbatim into <dd>, so neither can be escaped away — reject instead.
            if "|" in value or "\n" in value:
                sys.exit(f"gen-glossary: entry {i} field {field} must not contain '|' or a newline")
        key = entry["term"].casefold()
        if key in seen:
            sys.exit(f"gen-glossary: duplicate term {entry['term']!r} (entries {seen[key]} and {i})")
        seen[key] = i
    return entries


def render(entries: list[dict]) -> str:
    rows = []
    for entry in sorted(entries, key=sort_key):
        head = entry["term"]
        if entry.get("abbr"):
            head = f"{head} ({entry['abbr']})"
        rows.append(f"| **{head}** | {entry['definition'].strip()} |")
    return FRONT_MATTER + "\n" + PREAMBLE + "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if docs/glossary.md is stale",
    )
    args = parser.parse_args()

    entries = load_terms()
    want = render(entries)

    if args.check:
        have = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if have != want:
            print(
                f"gen-glossary: {TARGET.relative_to(REPO)} is stale — run `make glossary` and "
                "commit the result",
                file=sys.stderr,
            )
            return 1
        print(f"gen-glossary: {TARGET.relative_to(REPO)} is up to date ({len(entries)} terms)")
        return 0

    TARGET.write_text(want, encoding="utf-8")
    print(f"gen-glossary: wrote {TARGET.relative_to(REPO)} ({len(entries)} terms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
