#!/usr/bin/env python3
"""Generate API reference markdown from rSwitch C headers/modules."""

import argparse
import glob
import os
import re
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_PATH = os.path.join(ROOT, "docs", "development", "API_Reference_Generated.md")

MODULE_GLOB = os.path.join(ROOT, "bpf", "modules", "*.bpf.c")
MODULE_ABI_H = os.path.join(ROOT, "bpf", "core", "module_abi.h")
UAPI_H = os.path.join(ROOT, "bpf", "core", "uapi.h")
MAP_DEFS_H = os.path.join(ROOT, "bpf", "core", "map_defs.h")
RSWITCH_BPF_H = os.path.join(ROOT, "bpf", "include", "rswitch_bpf.h")

STRUCT_TARGETS = [
    "rs_ctx",
    "rs_layers",
    "rs_port_config",
    "rs_mac_key",
    "rs_mac_entry",
    "rs_vlan_members",
    "rs_stats",
    "rs_module_stats",
    "rs_module_config_key",
    "rs_module_config_value",
    "rs_module_desc",
    "rs_module_deps",
]

MACRO_TARGETS = [
    "RS_GET_CTX",
    "RS_TAIL_CALL_NEXT",
    "RS_TAIL_CALL_EGRESS",
    "RS_EMIT_EVENT",
    "RS_DECLARE_MODULE",
    "RS_DEPENDS_ON",
    "RS_API_STABLE",
    "RS_API_EXPERIMENTAL",
    "RS_API_INTERNAL",
]


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def split_top_level_args(arg_text):
    args = []
    cur = []
    depth = 0
    in_str = False
    esc = False
    quote = ""
    for ch in arg_text:
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ("\"", "'"):
            in_str = True
            quote = ch
            cur.append(ch)
            continue
        if ch == "(":
            depth += 1
            cur.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
            continue
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def clean_c_string(token):
    token = token.strip()
    if token.startswith('"') and token.endswith('"') and len(token) >= 2:
        return token[1:-1]
    return token


def find_matching_brace(text, open_idx):
    depth = 0
    i = open_idx
    in_str = False
    esc = False
    quote = ""
    while i < len(text):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ("\"", "'"):
            in_str = True
            quote = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def extract_named_struct(text, name):
    m = re.search(r"(?:^|\n)\s*(?:RS_API_\w+\s+)?struct\s+%s\s*\{" % re.escape(name), text)
    if not m:
        return None
    start = m.start()
    open_idx = text.find("{", m.end() - 1)
    close_idx = find_matching_brace(text, open_idx)
    if close_idx < 0:
        return None
    semi_idx = text.find(";", close_idx)
    if semi_idx < 0:
        return None
    return text[start:semi_idx + 1].strip()


def extract_macro_definition(text, name):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"\s*#define\s+%s\b" % re.escape(name), line):
            block = [line.rstrip()]
            i += 1
            while block[-1].endswith("\\") and i < len(lines):
                block.append(lines[i].rstrip())
                i += 1
            return "\n".join(block)
        i += 1
    return None


def extract_define_table(text, prefix):
    out = []
    for line in text.splitlines():
        m = re.match(r"^[ \t]*#define[ \t]+(%s\w*)[ \t]+(.+)$" % re.escape(prefix), line)
        if not m:
            continue
        name = m.group(1).strip()
        rest = m.group(2).strip()
        comment = ""
        cm = re.search(r"/\*\s*(.*?)\s*\*/[ \t]*$", rest)
        if cm:
            comment = cm.group(1).strip()
            rest = rest[:cm.start()].rstrip()
        out.append({"name": name, "value": rest, "comment": comment})
    return out


def resolve_values(defs):
    symbols = {d["name"]: d["value"] for d in defs}

    def _resolve_expr(expr, seen):
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", expr))
        for t in sorted(tokens, key=len, reverse=True):
            if t in symbols and t not in seen:
                rep = _resolve_expr(symbols[t], seen | {t})
                expr = re.sub(r"\b%s\b" % re.escape(t), "(%s)" % rep, expr)
        return expr

    for d in defs:
        expr = _resolve_expr(d["value"], {d["name"]})
        if re.fullmatch(r"[\s0-9xa-fA-FuUlL()+\-*/%<>&|^~]+", expr):
            try:
                val = eval(expr.replace("u", "").replace("U", "").replace("l", "").replace("L", ""), {"__builtins__": {}})
                d["resolved"] = str(val)
            except Exception:
                d["resolved"] = ""
        else:
            d["resolved"] = ""
    return defs


def extract_module_registry(module_paths):
    rows = []
    for path in sorted(module_paths):
        text = read_file(path)
        for m in re.finditer(r"RS_DECLARE_MODULE\s*\((.*?)\)\s*;", text, re.S):
            args = split_top_level_args(strip_c_comments(m.group(1)))
            if len(args) < 5:
                continue
            rows.append(
                {
                    "name": clean_c_string(args[0]),
                    "hook": args[1].strip(),
                    "stage": args[2].strip(),
                    "flags": args[3].strip(),
                    "description": clean_c_string(args[4]),
                    "source": os.path.relpath(path, ROOT),
                }
            )
    def stage_key(v):
        m = re.match(r"\d+", v["stage"])
        return int(m.group(0)) if m else 1_000_000
    rows.sort(key=lambda x: (x["hook"], stage_key(x), x["name"]))
    return rows


def extract_helpers(text, relpath):
    out = []
    for m in re.finditer(r"(?:RS_API_\w+\s+)?static\s+__always_inline\b", text):
        start = m.start()
        brace = text.find("{", start)
        if brace < 0:
            continue
        header = text[start:brace].strip()
        if ";" in header:
            continue
        signature = " ".join(header.split())
        fm = re.search(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$", signature)
        if not fm:
            continue
        name = fm.group(1)
        out.append({"name": name, "signature": signature, "source": relpath})
    seen = set()
    uniq = []
    for h in out:
        key = (h["name"], h["source"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(h)
    uniq.sort(key=lambda x: (x["source"], x["name"]))
    return uniq


def extract_maps(text, relpath):
    rows = []
    for m in re.finditer(r"(?:^|\n)\s*(?!extern\b)struct\s*\{(.*?)\}\s*([A-Za-z_]\w*)\s+SEC\(\"\.maps\"\)\s*;", text, re.S):
        body = m.group(1)
        name = m.group(2)
        entries = {
            "type": "",
            "max_entries": "",
            "key": "",
            "value": "",
            "pinning": "",
        }
        for kind in ("type", "max_entries", "key", "value", "pinning"):
            km = re.search(r"__%s\(\s*%s\s*,\s*([^\)]+)\);" % (("uint" if kind in ("type", "max_entries", "pinning") else "type"), kind), body)
            if km:
                entries[kind] = " ".join(km.group(1).split())
        rows.append(
            {
                "name": name,
                "type": entries["type"],
                "key": entries["key"],
                "value": entries["value"],
                "max_entries": entries["max_entries"],
                "pinning": entries["pinning"],
                "source": relpath,
            }
        )
    rows.sort(key=lambda x: (x["source"], x["name"]))
    return rows


def md_table(headers, rows):
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out)


def esc_md(s):
    return (s or "").replace("|", "\\|").strip()


def build_markdown(data):
    lines = []
    lines.append("# API Reference (Generated)")
    lines.append("")
    lines.append("This file is auto-generated by `scripts/gen_api_docs.py`. Do not edit manually.")
    lines.append("")
    lines.append("## Contents")
    lines.append("- [Module Registry](#module-registry)")
    lines.append("- [Capability Flags](#capability-flags)")
    lines.append("- [Error Codes](#error-codes)")
    lines.append("- [Drop Reasons](#drop-reasons)")
    lines.append("- [Event Types](#event-types)")
    lines.append("- [Data Structures](#data-structures)")
    lines.append("- [Helper Functions](#helper-functions)")
    lines.append("- [BPF Maps](#bpf-maps)")
    lines.append("- [Macros](#macros)")
    lines.append("- [ABI Version](#abi-version)")
    lines.append("")

    lines.append("## Module Registry")
    module_rows = [
        [
            "`%s`" % esc_md(m["name"]),
            "`%s`" % esc_md(m["hook"]),
            "`%s`" % esc_md(m["stage"]),
            "`%s`" % esc_md(m["flags"]),
            esc_md(m["description"]),
            "`%s`" % esc_md(m["source"]),
        ]
        for m in data["modules"]
    ]
    lines.append(md_table(["Module", "Hook", "Stage", "Flags", "Description", "Source"], module_rows))
    lines.append("")

    def add_define_section(title, defs):
        lines.append("## %s" % title)
        rows = []
        for d in defs:
            rows.append([
                "`%s`" % esc_md(d["name"]),
                "`%s`" % esc_md(d["value"]),
                esc_md(d.get("resolved", "")),
                esc_md(d["comment"]),
            ])
        lines.append(md_table(["Name", "Value", "Resolved", "Comment"], rows))
        lines.append("")

    add_define_section("Capability Flags", data["flags"])
    add_define_section("Error Codes", data["errors"])
    add_define_section("Drop Reasons", data["drops"])
    add_define_section("Event Types", data["events"])

    lines.append("## Data Structures")
    for s in data["structs"]:
        lines.append("### `struct %s`" % s["name"])
        lines.append("Source: `%s`" % s["source"])
        lines.append("")
        lines.append("```c")
        lines.append(s["code"])
        lines.append("```")
        lines.append("")

    lines.append("## Helper Functions")
    helper_rows = [
        ["`%s`" % h["name"], "`%s`" % esc_md(h["source"])]
        for h in data["helpers"]
    ]
    lines.append(md_table(["Function", "Source"], helper_rows))
    lines.append("")
    for h in data["helpers"]:
        lines.append("### `%s`" % h["name"])
        lines.append("Source: `%s`" % h["source"])
        lines.append("")
        lines.append("```c")
        lines.append(h["signature"] + ";")
        lines.append("```")
        lines.append("")

    lines.append("## BPF Maps")
    map_rows = []
    for m in data["maps"]:
        map_rows.append([
            "`%s`" % esc_md(m["name"]),
            "`%s`" % esc_md(m["type"]),
            "`%s`" % esc_md(m["key"]),
            "`%s`" % esc_md(m["value"]),
            "`%s`" % esc_md(m["max_entries"]),
            "`%s`" % esc_md(m["pinning"]),
            "`%s`" % esc_md(m["source"]),
        ])
    lines.append(md_table(["Map", "Type", "Key", "Value", "Max Entries", "Pinning", "Source"], map_rows))
    lines.append("")

    lines.append("## Macros")
    for m in data["macros"]:
        lines.append("### `%s`" % m["name"])
        lines.append("Source: `%s`" % m["source"])
        lines.append("")
        lines.append("```c")
        lines.append(m["code"])
        lines.append("```")
        lines.append("")

    lines.append("## ABI Version")
    abi = data["abi"]
    lines.append("- `RS_ABI_VERSION_MAJOR`: `%s`" % esc_md(abi.get("RS_ABI_VERSION_MAJOR", "")))
    lines.append("- `RS_ABI_VERSION_MINOR`: `%s`" % esc_md(abi.get("RS_ABI_VERSION_MINOR", "")))
    lines.append("- `RS_ABI_VERSION`: `%s`" % esc_md(abi.get("RS_ABI_VERSION", "")))
    lines.append("- `RS_ABI_VERSION_1`: `%s`" % esc_md(abi.get("RS_ABI_VERSION_1", "")))
    lines.append("")

    return "\n".join(lines)


def collect_data():
    module_abi_text = read_file(MODULE_ABI_H)
    uapi_text = read_file(UAPI_H)
    map_defs_text = read_file(MAP_DEFS_H)
    rswitch_bpf_text = read_file(RSWITCH_BPF_H)

    module_paths = sorted(glob.glob(MODULE_GLOB))

    data = {}
    data["modules"] = extract_module_registry(module_paths)

    data["flags"] = resolve_values(extract_define_table(module_abi_text, "RS_FLAG_"))
    data["errors"] = resolve_values(extract_define_table(uapi_text, "RS_ERROR_"))
    data["drops"] = resolve_values(extract_define_table(uapi_text, "RS_DROP_"))
    data["events"] = resolve_values(extract_define_table(uapi_text, "RS_EVENT_"))

    structs = []
    struct_sources = {
        "rs_ctx": (uapi_text, os.path.relpath(UAPI_H, ROOT)),
        "rs_layers": (uapi_text, os.path.relpath(UAPI_H, ROOT)),
        "rs_port_config": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_mac_key": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_mac_entry": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_vlan_members": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_stats": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_module_stats": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_module_config_key": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_module_config_value": (map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)),
        "rs_module_desc": (module_abi_text, os.path.relpath(MODULE_ABI_H, ROOT)),
        "rs_module_deps": (module_abi_text, os.path.relpath(MODULE_ABI_H, ROOT)),
    }
    for name in STRUCT_TARGETS:
        text, src = struct_sources[name]
        code = extract_named_struct(text, name)
        if code:
            structs.append({"name": name, "source": src, "code": code})
    data["structs"] = structs

    helpers = []
    helpers.extend(extract_helpers(rswitch_bpf_text, os.path.relpath(RSWITCH_BPF_H, ROOT)))
    helpers.extend(extract_helpers(map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)))
    helpers.sort(key=lambda x: (x["source"], x["name"]))
    data["helpers"] = helpers

    maps = []
    maps.extend(extract_maps(uapi_text, os.path.relpath(UAPI_H, ROOT)))
    maps.extend(extract_maps(map_defs_text, os.path.relpath(MAP_DEFS_H, ROOT)))
    data["maps"] = maps

    macros = []
    macro_sources = [
        (uapi_text, os.path.relpath(UAPI_H, ROOT)),
        (module_abi_text, os.path.relpath(MODULE_ABI_H, ROOT)),
        (rswitch_bpf_text, os.path.relpath(RSWITCH_BPF_H, ROOT)),
    ]
    for name in MACRO_TARGETS:
        found = None
        src = ""
        for text, rel in macro_sources:
            found = extract_macro_definition(text, name)
            if found:
                src = rel
                break
        if found:
            macros.append({"name": name, "source": src, "code": found})
    data["macros"] = macros

    abi_keys = ["RS_ABI_VERSION_MAJOR", "RS_ABI_VERSION_MINOR", "RS_ABI_VERSION", "RS_ABI_VERSION_1"]
    abi = {}
    for k in abi_keys:
        m = re.search(r"^\s*#define\s+%s\s+(.+?)\s*$" % re.escape(k), module_abi_text, re.M)
        if m:
            abi[k] = m.group(1).strip()
    data["abi"] = abi

    return data


def main():
    parser = argparse.ArgumentParser(description="Generate rSwitch API markdown reference")
    parser.add_argument("--check", action="store_true", help="exit 1 if output differs from committed file")
    args = parser.parse_args()

    data = collect_data()
    md = build_markdown(data)

    if args.check:
        if not os.path.exists(OUT_PATH):
            print("missing generated file: %s" % os.path.relpath(OUT_PATH, ROOT), file=sys.stderr)
            return 1
        current = read_file(OUT_PATH)
        if current != md:
            print("generated API docs are out of date", file=sys.stderr)
            return 1
        return 0

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(md)
        if not md.endswith("\n"):
            f.write("\n")
    print("wrote %s" % os.path.relpath(OUT_PATH, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
