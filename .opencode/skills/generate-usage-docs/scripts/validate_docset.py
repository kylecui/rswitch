#!/usr/bin/env python3
"""
Validate a generated documentation set.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_FILES = [
    "README.md",
]

RECOMMENDED_DOCS = [
    "docs/quickstart.md",
    "docs/configuration.md",
    "docs/usage.md",
    "docs/troubleshooting.md",
]

README_HEADINGS = [
    "# ",
    "## Quick Start",
    "## Configuration",
]

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a generated documentation set.")
    parser.add_argument("root", help="Root directory of the generated docset")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(json.dumps({"ok": False, "error": f"path not found: {root}"}))
        return 2

    missing_required = [p for p in REQUIRED_FILES if not (root / p).exists()]
    missing_recommended = [p for p in RECOMMENDED_DOCS if not (root / p).exists()]

    readme_checks = {}
    readme_path = root / "README.md"
    if readme_path.exists():
        content = readme_path.read_text(encoding="utf-8", errors="ignore")
        for heading in README_HEADINGS:
            readme_checks[heading.strip()] = heading in content

    ok = not missing_required
    print(json.dumps({
        "ok": ok,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "readme_checks": readme_checks,
    }, ensure_ascii=False, indent=2))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
