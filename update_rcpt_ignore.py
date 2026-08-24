#!/usr/bin/env python3
"""Interactively add current PMG quarantine recipients to rcpt_ignore."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quarantine_sentinel import PMGClient, PMGError, load_config


def _find_array_span(source: str) -> tuple[int, int]:
    """Locate the rcpt_ignore array and return the offsets of its brackets.

    The span starts at the `rcpt_ignore` key and ends just past the matching
    closing bracket, so both single-line and multiline arrays are covered.
    """
    match = re.search(r"(?m)^[ \t]*(rcpt_ignore[ \t]*=[ \t]*\[)", source)
    if not match:
        raise ValueError("no rcpt_ignore list found in the configuration")

    index = match.end() - 1  # the opening bracket
    depth = 0
    quote: str | None = None
    while index < len(source):
        char = source[index]
        if quote is not None:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            newline = source.find("\n", index)
            if newline == -1:
                break
            index = newline
            continue
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return match.start(1), index + 1
        index += 1

    raise ValueError("rcpt_ignore list is not terminated in the configuration")


def add_recipients_to_config(path: Path, recipients: list[str]) -> None:
    """Append recipients to the existing rcpt_ignore TOML array.

    Both layouts are handled: a multiline array keeps one entry per line, a
    single-line array stays on its line.
    """
    if not recipients:
        return

    source = path.read_text(encoding="utf-8")
    start, end = _find_array_span(source)
    inner = source[source.index("[", start) + 1:end - 1]

    if "\n" in inner:
        # Multiline: insert new entries just before the closing bracket's line,
        # indented like the existing ones.
        entry_lines = [line for line in inner.splitlines() if line.strip()]
        indent = re.match(r"[ \t]*", entry_lines[0]).group() if entry_lines else "  "
        insert_at = source.rindex("\n", start, end - 1) + 1
        additions = "".join(f"{indent}{json.dumps(address)},\n" for address in recipients)
        updated = source[:insert_at] + additions + source[insert_at:]
    else:
        existing = inner.strip()
        addition = ", ".join(json.dumps(address) for address in recipients)
        if not existing:
            new_inner = addition
        elif existing.endswith(","):
            new_inner = f"{existing} {addition}"
        else:
            new_inner = f"{existing}, {addition}"
        updated = source[:start] + f"rcpt_ignore = [{new_inner}]" + source[end:]

    path.write_text(updated, encoding="utf-8")


def wants_to_ignore(address: str) -> bool:
    answer = input(f"Add {address} to the ignore list? [y/N] ").strip().casefold()
    return answer in {"y", "yes", "j", "ja"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Interactively ignore current PMG quarantine recipients"
    )
    parser.add_argument(
        "-c", "--config", default="config.toml", help="Path to the TOML configuration"
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Configuration not found: {config_path}", file=sys.stderr)
        return 1

    cfg = load_config(str(config_path))
    since = datetime.now(timezone.utc) - timedelta(days=cfg.lookback_days)

    try:
        users = PMGClient(cfg).list_quarantine_users(since)
    except PMGError as exc:
        print(f"PMG query failed: {exc}", file=sys.stderr)
        return 1

    ignored = set(cfg.rcpt_ignore)
    candidates = sorted(
        {
            address.strip()
            for address in users
            if address.strip() and address.strip().casefold() not in ignored
        },
        key=str.casefold,
    )

    if not candidates:
        print("No new quarantine recipients found.")
        return 0

    print(f"{len(candidates)} recipient(s) not yet ignored found.")
    selected = [address for address in candidates if wants_to_ignore(address)]

    if not selected:
        print("No changes made.")
        return 0

    try:
        add_recipients_to_config(config_path, selected)
    except (OSError, ValueError) as exc:
        print(f"Could not update configuration: {exc}", file=sys.stderr)
        return 1

    print(f"Added {len(selected)} recipient(s) to {config_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
