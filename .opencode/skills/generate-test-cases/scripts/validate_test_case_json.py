#!/usr/bin/env python3
"""
Validate generated test-case JSON structure.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED_CASE_KEYS = [
    "id",
    "title",
    "objective",
    "target",
    "preconditions",
    "steps",
    "expected_results",
    "priority",
    "risk",
]

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a generated test-case JSON file.")
    parser.add_argument("input", help="Path to test-cases JSON")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(json.dumps({"ok": False, "error": f"file not found: {path}"}))
        return 2

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"invalid json: {exc}"}))
        return 2

    cases = data.get("test_cases")
    if not isinstance(cases, list):
        print(json.dumps({"ok": False, "error": "top-level key 'test_cases' must be a list"}))
        return 2

    errors = []
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"case[{idx}] is not an object")
            continue
        for key in REQUIRED_CASE_KEYS:
            if key not in case:
                errors.append(f"case[{idx}] missing key: {key}")
        if "steps" in case and not isinstance(case["steps"], list):
            errors.append(f"case[{idx}] 'steps' must be a list")
        if "expected_results" in case and not isinstance(case["expected_results"], list):
            errors.append(f"case[{idx}] 'expected_results' must be a list")

    print(json.dumps({
        "ok": not errors,
        "case_count": len(cases),
        "errors": errors,
    }, ensure_ascii=False, indent=2))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
