#!/usr/bin/env python3
"""
Inventory a repository for skill-driven analysis.
Emits structured JSON to stdout and diagnostics to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

MAX_FILES_PER_BUCKET = 80
TEXT_EXTS = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".proto",
    ".graphql",
    ".sql",
}

API_HINTS = {
    "openapi",
    "swagger",
    "postman",
    "proto",
    "graphql",
    "routes",
    "controller",
    "api",
}
CONFIG_HINTS = {
    "config",
    ".env",
    "settings",
    "application.yml",
    "application.yaml",
    "docker-compose",
    "compose.yml",
    "compose.yaml",
}
DOC_HINTS = {
    "readme",
    "docs",
    "design",
    "architecture",
    "spec",
    "proposal",
    "manual",
    "guide",
}
TEST_HINTS = {
    "test",
    "tests",
    "spec",
    "e2e",
    "integration",
    "pytest",
    "playwright",
    "cypress",
    "jest",
    "vitest",
}
ENTRYPOINT_HINTS = {
    "main.py",
    "app.py",
    "server.py",
    "manage.py",
    "cli.py",
    "index.ts",
    "main.ts",
    "package.json",
    "pyproject.toml",
    "pom.xml",
    "go.mod",
    "cargo.toml",
}


def is_hidden_path(path: Path) -> bool:
    return any(
        part.startswith(".") and part not in {".github", ".opencode"}
        for part in path.parts
    )


def should_skip_dir(path: Path) -> bool:
    name = path.name.lower()
    return name in {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
        ".next",
    }


def bucket_for(path: Path) -> set[str]:
    s = str(path).lower()
    name = path.name.lower()
    buckets = set()

    if any(h in s for h in DOC_HINTS):
        buckets.add("docs")
    if any(h in s for h in API_HINTS):
        buckets.add("api_specs")
    if any(h in s for h in CONFIG_HINTS):
        buckets.add("configs")
    if any(h in s for h in TEST_HINTS):
        buckets.add("tests")
    if name in ENTRYPOINT_HINTS:
        buckets.add("entrypoints")
    if name in {"readme.md", "readme"}:
        buckets.add("readme")
    if path.suffix.lower() in {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rs",
        ".c",
        ".cc",
        ".cpp",
    }:
        buckets.add("source_code")
    return buckets


def infer_project_type(paths: list[Path]) -> list[str]:
    names = {p.name.lower() for p in paths}
    fulls = {str(p).lower() for p in paths}
    result = []

    if "package.json" in names:
        result.append("node-project")
    if "pyproject.toml" in names or "requirements.txt" in names or "setup.py" in names:
        result.append("python-project")
    if "pom.xml" in names or "build.gradle" in names or "build.gradle.kts" in names:
        result.append("jvm-project")
    if "go.mod" in names:
        result.append("go-project")
    if "cargo.toml" in names:
        result.append("rust-project")
    if any("openapi" in x or "swagger" in x for x in fulls):
        result.append("api-service")
    if any("/docs/" in x or x.endswith("/docs") for x in fulls):
        result.append("documented-project")
    if any("/tests/" in x or "/test/" in x for x in fulls):
        result.append("has-tests")
    if any("/cmd/" in x or "/cli/" in x for x in fulls):
        result.append("cli-oriented")
    return result or ["unknown"]


def summarize_bucket(bucket_paths: list[Path], base: Path) -> list[str]:
    items = []
    for p in bucket_paths[:MAX_FILES_PER_BUCKET]:
        try:
            items.append(str(p.relative_to(base)))
        except ValueError:
            items.append(str(p))
    return items


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a project and emit structured inventory JSON for OpenCode skills.",
    )
    parser.add_argument("root", nargs="?", default=".", help="Project root to scan")
    parser.add_argument(
        "--max-files", type=int, default=4000, help="Hard cap on scanned files"
    )
    args = parser.parse_args()

    base = Path(args.root).resolve()
    if not base.exists():
        print(json.dumps({"error": f"Path not found: {base}"}))
        return 2

    scanned: list[Path] = []
    buckets: dict[str, list[Path]] = {
        "readme": [],
        "docs": [],
        "api_specs": [],
        "configs": [],
        "tests": [],
        "entrypoints": [],
        "source_code": [],
    }

    count = 0
    for current_root, dirnames, filenames in os.walk(base):
        root_path = Path(current_root)
        dirnames[:] = [d for d in dirnames if not should_skip_dir(root_path / d)]
        if is_hidden_path(root_path.relative_to(base)) if root_path != base else False:
            continue

        for filename in filenames:
            if count >= args.max_files:
                break
            p = root_path / filename
            count += 1
            if p.suffix.lower() not in TEXT_EXTS and filename.lower() not in {
                "readme",
                "dockerfile",
                "makefile",
            }:
                continue
            scanned.append(p)
            for bucket in bucket_for(p):
                if bucket in buckets:
                    buckets[bucket].append(p)
        if count >= args.max_files:
            break

    result = {
        "root": str(base),
        "project_types": infer_project_type(scanned),
        "counts": {k: len(v) for k, v in buckets.items()},
        "buckets": {k: summarize_bucket(v, base) for k, v in buckets.items()},
        "notes": [
            "Inventory is heuristic and intended to guide the skill, not replace judgment.",
            "Use bucket files as starting points for reading and synthesis.",
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
