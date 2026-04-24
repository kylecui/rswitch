#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Normalize Petfish-style Chinese-English technical writing.

Usage:
  uv run scripts/normalize_text.py --text "接入层支持 Webhook 挂载。"
  uv run scripts/normalize_text.py --file input.md --output output.md
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

CJK = r"\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"

# Common multi-token technical phrases that should stay compact in Petfish style.
TECH_PHRASE_FIXES = {
    "API 接口": "API接口",
    "API 网关": "API网关",
    "TCP 连接": "TCP连接",
    "TLS 握手": "TLS握手",
    "HTTP 请求": "HTTP请求",
    "HTTPS 请求": "HTTPS请求",
    "DNS 查询": "DNS查询",
    "Git 提交": "Git提交",
    "Git 分支": "Git分支",
    "Git 仓库": "Git仓库",
    "Webhook 挂载": "Webhook挂载",
    "Issue 更新": "Issue更新",
    "PR 合并": "PR合并",
    "JSON 格式": "JSON格式",
    "Markdown 文档": "Markdown文档",
    "XDP 程序": "XDP程序",
    "eBPF 映射": "eBPF映射",
    "AF_XDP 队列": "AF_XDP队列",
    "OpenCode 项目": "OpenCode项目",
}


def normalize_zh_en_spacing(text: str) -> str:
    """Remove unnecessary spaces between Chinese and English technical terms."""
    for src, dst in TECH_PHRASE_FIXES.items():
        text = text.replace(src, dst)

    # Chinese + spaces + ASCII technical token -> compact
    text = re.sub(rf"([{CJK}])\s+([A-Za-z][A-Za-z0-9_./+-]*)", r"\1\2", text)
    # ASCII technical token + spaces + Chinese -> compact
    text = re.sub(rf"([A-Za-z][A-Za-z0-9_./+-]*)\s+([{CJK}])", r"\1\2", text)
    # Chinese + spaces + number + common unit/percent -> compact
    text = re.sub(rf"([{CJK}])\s+(\d+(?:\.\d+)?%?)", r"\1\2", text)
    text = re.sub(rf"(\d+(?:\.\d+)?)\s+([{CJK}])", r"\1\2", text)
    return text


def normalize_punctuation(text: str) -> str:
    """Apply conservative punctuation and whitespace cleanup."""
    # Collapse repeated spaces but preserve newlines and indentation roughly.
    text = re.sub(r"[ \t]+", " ", text)
    # Remove spaces before Chinese punctuation.
    text = re.sub(r"\s+([，。；：！？、])", r"\1", text)
    # Remove spaces after opening Chinese quotation/bracket and before closing ones.
    text = re.sub("([\u201c\u2018\uff08\u300a\u3010])\\s+", r"\1", text)
    text = re.sub("\\s+([\u201d\u2019\uff09\u300b\u3011])", r"\1", text)
    return text


def normalize(text: str) -> str:
    text = normalize_punctuation(text)
    text = normalize_zh_en_spacing(text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize Petfish-style Chinese-English technical text."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="Input text to normalize")
    src.add_argument("--file", help="Input file path")
    parser.add_argument("--output", help="Optional output file path")
    args = parser.parse_args()

    if args.file:
        content = Path(args.file).read_text(encoding="utf-8")
    else:
        content = args.text

    result = normalize(content)

    if args.output:
        Path(args.output).write_text(result, encoding="utf-8")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
