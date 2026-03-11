#!/usr/bin/env python3
"""
rSwitch Intent Translation Engine

Translates high-level network intents into rSwitch profiles and module configurations.
Intents describe WHAT the network should do; this engine determines HOW.

Usage:
    python3 scripts/intent_engine.py <intent.yaml> [-o output_dir] [--dry-run] [--validate]
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import yaml


MODULE_STAGES = {
    "dispatcher": 10,
    "lacp": 11,
    "lldp": 11,
    "stp": 12,
    "tunnel": 15,
    "source_guard": 18,
    "dhcp_snoop": 19,
    "vlan": 20,
    "qos_classify": 25,
    "rate_limiter": 28,
    "acl": 30,
    "conntrack": 32,
    "mirror": 45,
    "route": 50,
    "nat": 55,
    "flow_table": 60,
    "l2learn": 80,
    "sflow": 85,
    "lastcall": 90,
}

EGRESS_MODULES = {
    "egress": 160,
    "egress_qos": 170,
    "egress_vlan": 180,
    "egress_final": 190,
}

QOS_CLASS_MAP = {
    "best-effort": 0,
    "bulk": 1,
    "video": 2,
    "voice": 3,
    "control": 4,
    "critical": 5,
}


@dataclass
class ValidationResult:
    errors: List[str]
    warnings: List[str]

    @property
    def ok(self) -> bool:
        return not self.errors


def _intent_root(doc: Dict[str, Any]) -> Dict[str, Any]:
    intent = doc.get("intent")
    if not isinstance(intent, dict):
        raise ValueError("Intent file must contain top-level 'intent:' mapping")
    return intent


def parse_intent(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise ValueError(f"Intent file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Intent file must parse to a YAML mapping")

    intent = _intent_root(data)

    result = validate_intent(intent)
    if not result.ok:
        error_msg = "\n".join(f"- {msg}" for msg in result.errors)
        raise ValueError(f"Intent validation failed:\n{error_msg}")

    return intent


def validate_intent(intent: Dict[str, Any]) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []

    name = intent.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("intent.name is required and must be a non-empty string")
    elif not re.match(r"^[a-zA-Z0-9_-]+$", name):
        errors.append("intent.name may contain only letters, numbers, '_' and '-'")

    description = intent.get("description", "")
    if description is not None and not isinstance(description, str):
        errors.append("intent.description must be a string")

    segments = intent.get("segments", [])
    if segments is None:
        segments = []
    if not isinstance(segments, list):
        errors.append("intent.segments must be a list")
        segments = []

    seen_segment_names = set()
    seen_vlans = set()
    seen_ports: Dict[int, str] = {}

    for idx, seg in enumerate(segments):
        pfx = f"intent.segments[{idx}]"
        if not isinstance(seg, dict):
            errors.append(f"{pfx} must be a mapping")
            continue

        seg_name = seg.get("name")
        if not isinstance(seg_name, str) or not seg_name.strip():
            errors.append(f"{pfx}.name must be a non-empty string")
        elif seg_name in seen_segment_names:
            errors.append(f"Duplicate segment name: {seg_name}")
        else:
            seen_segment_names.add(seg_name)

        vlan = seg.get("vlan")
        if not isinstance(vlan, int):
            errors.append(f"{pfx}.vlan must be an integer")
        elif vlan < 1 or vlan > 4094:
            errors.append(f"{pfx}.vlan must be in range 1-4094")
        elif vlan in seen_vlans:
            errors.append(f"Duplicate VLAN ID across segments: {vlan}")
        else:
            seen_vlans.add(vlan)

        ports = seg.get("ports", [])
        if not isinstance(ports, list):
            errors.append(f"{pfx}.ports must be a list of integers")
            continue

        for port in ports:
            if not isinstance(port, int):
                errors.append(f"{pfx}.ports contains non-integer value: {port!r}")
                continue
            if port < 1 or port > 4096:
                errors.append(f"{pfx}.ports contains out-of-range port: {port}")
                continue
            owner = seen_ports.get(port)
            if owner is not None and owner != seg_name:
                errors.append(f"Port {port} assigned to multiple segments: {owner}, {seg_name}")
            else:
                seen_ports[port] = str(seg_name)

    for section_name in (
        "security",
        "qos",
        "monitoring",
        "routing",
        "high_availability",
        "tunnels",
        "ecmp",
    ):
        section = intent.get(section_name, {})
        if section is None:
            section = {}
        if not isinstance(section, dict):
            errors.append(f"intent.{section_name} must be a mapping")

    security = intent.get("security", {}) or {}
    for field in ("acl", "source_guard", "dhcp_snooping"):
        if field in security and not isinstance(security[field], bool):
            errors.append(f"intent.security.{field} must be true/false")

    qos = intent.get("qos", {}) or {}
    if "enabled" in qos and not isinstance(qos.get("enabled"), bool):
        errors.append("intent.qos.enabled must be true/false")
    qos_default_class = qos.get("default_class", "best-effort")
    if qos.get("enabled"):
        if not isinstance(qos_default_class, str):
            errors.append("intent.qos.default_class must be a string when QoS is enabled")
        elif qos_default_class not in QOS_CLASS_MAP:
            errors.append(
                "intent.qos.default_class must be one of: "
                + ", ".join(sorted(QOS_CLASS_MAP.keys()))
            )

    monitoring = intent.get("monitoring", {}) or {}
    for field in ("sflow", "mirror", "telemetry"):
        if field in monitoring and not isinstance(monitoring[field], bool):
            errors.append(f"intent.monitoring.{field} must be true/false")

    routing = intent.get("routing", {}) or {}
    if "enabled" in routing and not isinstance(routing.get("enabled"), bool):
        errors.append("intent.routing.enabled must be true/false")
    if routing.get("enabled") and not segments:
        warnings.append("Routing is enabled but no segments were defined")

    ha = intent.get("high_availability", {}) or {}
    for field in ("stp", "lacp"):
        if field in ha and not isinstance(ha[field], bool):
            errors.append(f"intent.high_availability.{field} must be true/false")

    tunnels = intent.get("tunnels", {}) or {}
    if "enabled" in tunnels and not isinstance(tunnels.get("enabled"), bool):
        errors.append("intent.tunnels.enabled must be true/false")

    ecmp = intent.get("ecmp", {}) or {}
    if "enabled" in ecmp and not isinstance(ecmp.get("enabled"), bool):
        errors.append("intent.ecmp.enabled must be true/false")

    if ha.get("lacp") and segments and len(segments) < 2:
        warnings.append("LACP is enabled with only one segment; verify uplink intent")

    if security.get("source_guard") and not security.get("dhcp_snooping"):
        warnings.append("source_guard works best with dhcp_snooping enabled")

    return ValidationResult(errors=errors, warnings=warnings)


def _sorted_modules(modules: Sequence[str], stage_map: Dict[str, int]) -> List[str]:
    return sorted(set(modules), key=lambda m: (stage_map.get(m, 999), m))


def resolve_modules(intent: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    ingress_modules = ["dispatcher", "l2learn", "lastcall"]
    egress_modules = ["egress", "egress_final"]

    segments = intent.get("segments") or []
    if segments:
        ingress_modules.append("vlan")
        egress_modules.append("egress_vlan")

    security = intent.get("security", {}) or {}
    if security.get("acl"):
        ingress_modules.append("acl")
    if security.get("source_guard"):
        ingress_modules.append("source_guard")
    if security.get("dhcp_snooping"):
        ingress_modules.append("dhcp_snoop")

    qos = intent.get("qos", {}) or {}
    if qos.get("enabled"):
        ingress_modules.extend(["qos_classify", "rate_limiter"])

    monitoring = intent.get("monitoring", {}) or {}
    if monitoring.get("sflow"):
        ingress_modules.append("sflow")
    if monitoring.get("mirror"):
        ingress_modules.append("mirror")

    routing = intent.get("routing", {}) or {}
    if routing.get("enabled"):
        ingress_modules.extend(["route", "conntrack", "nat"])

    tunnels = intent.get("tunnels", {}) or {}
    if tunnels.get("enabled"):
        ingress_modules.append("tunnel")

    ecmp = intent.get("ecmp", {}) or {}
    if ecmp.get("enabled"):
        ingress_modules.append("flow_table")

    high_availability = intent.get("high_availability", {}) or {}
    if high_availability.get("stp"):
        ingress_modules.append("stp")
    if high_availability.get("lacp"):
        ingress_modules.append("lacp")

    return (
        _sorted_modules(ingress_modules, MODULE_STAGES),
        _sorted_modules(egress_modules, EGRESS_MODULES),
    )


def generate_vlan_config(segments: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    vlans: List[Dict[str, Any]] = []
    port_vlan_map: Dict[str, int] = {}

    for segment in segments:
        ports = [int(p) for p in segment.get("ports", [])]
        vlan = int(segment["vlan"])
        vlans.append(
            {
                "name": segment["name"],
                "vlan_id": vlan,
                "access_ports": ports,
            }
        )
        for port in ports:
            port_vlan_map[str(port)] = vlan

    return {
        "default_vlan": 1,
        "vlans": vlans,
        "port_vlan_map": port_vlan_map,
    }


def generate_acl_config(security: Dict[str, Any]) -> Dict[str, Any]:
    rules = [
        {
            "id": 10,
            "action": "allow",
            "match": {"proto": "arp"},
            "description": "Allow ARP for neighbor discovery",
        },
        {
            "id": 20,
            "action": "allow",
            "match": {"proto": "icmp"},
            "description": "Allow ICMP for network diagnostics",
        },
    ]

    if security.get("dhcp_snooping"):
        rules.append(
            {
                "id": 30,
                "action": "allow",
                "match": {"proto": "udp", "src_port": 67, "dst_port": 68},
                "description": "Allow DHCP server-to-client responses",
            }
        )

    rules.append(
        {
            "id": 999,
            "action": "allow",
            "match": {"any": True},
            "description": "Default permit (tighten for production hardening)",
        }
    )

    return {
        "enabled": True,
        "default_action": "permit",
        "rules": rules,
    }


def generate_qos_config(qos: Dict[str, Any]) -> Dict[str, Any]:
    default_class_name = str(qos.get("default_class", "best-effort"))
    default_class_id = QOS_CLASS_MAP.get(default_class_name, 0)

    return {
        "default_class": default_class_id,
        "class_map": QOS_CLASS_MAP,
        "rate_limits_mbps": {
            "best-effort": 1000,
            "bulk": 500,
            "video": 800,
            "voice": 200,
            "control": 150,
            "critical": 300,
        },
    }


def _generated_timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _build_profile_payload(
    intent: Dict[str, Any],
    ingress_modules: Sequence[str],
    egress_modules: Sequence[str],
) -> Dict[str, Any]:
    profile: Dict[str, Any] = {
        "name": intent["name"],
        "description": intent.get("description", ""),
        "modules": list(ingress_modules),
        "egress_modules": list(egress_modules),
        "config": {},
    }

    segments = intent.get("segments") or []
    if segments:
        profile["config"]["vlan"] = generate_vlan_config(segments)

    security = intent.get("security", {}) or {}
    if security.get("acl"):
        profile["config"]["acl"] = generate_acl_config(security)
    if security.get("source_guard"):
        profile["config"]["source_guard"] = {"enabled": True, "mode": "strict"}
    if security.get("dhcp_snooping"):
        profile["config"]["dhcp_snoop"] = {
            "enabled": True,
            "trusted_ports": [],
            "lease_timeout_sec": 3600,
        }

    qos = intent.get("qos", {}) or {}
    if qos.get("enabled"):
        qos_cfg = generate_qos_config(qos)
        profile["config"]["qos_classify"] = {
            "default_class": qos_cfg["default_class"],
            "class_map": qos_cfg["class_map"],
        }
        profile["config"]["rate_limiter"] = {
            "rates_mbps": qos_cfg["rate_limits_mbps"],
        }

    monitoring = intent.get("monitoring", {}) or {}
    if monitoring.get("sflow"):
        profile["config"]["sflow"] = {
            "enabled": True,
            "sample_rate": 4096,
            "collector": "127.0.0.1:6343",
        }
    if monitoring.get("mirror"):
        profile["config"]["mirror"] = {
            "enabled": True,
            "session_id": 1,
            "egress_port": None,
        }
    if monitoring.get("telemetry"):
        profile["config"]["telemetry"] = {
            "enabled": True,
            "interval_sec": 10,
        }

    if (intent.get("routing") or {}).get("enabled"):
        profile["config"]["route"] = {
            "enabled": True,
            "default_action": "lookup",
        }
        profile["config"]["conntrack"] = {
            "enabled": True,
            "max_entries": 65536,
        }
        profile["config"]["nat"] = {
            "enabled": True,
            "mode": "masquerade",
        }

    tunnels = intent.get("tunnels", {}) or {}
    if tunnels.get("enabled"):
        profile["config"]["tunnel"] = {
            "enabled": True,
            "type": tunnels.get("type", "vxlan"),
        }

    ecmp = intent.get("ecmp", {}) or {}
    if ecmp.get("enabled"):
        profile["config"]["flow_table"] = {
            "enabled": True,
            "mode": "ecmp",
            "max_paths": int(ecmp.get("max_paths", 16)),
        }

    ha = intent.get("high_availability", {}) or {}
    if ha.get("stp"):
        profile["config"]["stp"] = {
            "enabled": True,
            "bridge_priority": 32768,
        }
    if ha.get("lacp"):
        profile["config"]["lacp"] = {
            "enabled": True,
            "mode": "active",
        }

    if not profile["config"]:
        profile.pop("config")

    return profile


def _write_yaml(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False, default_flow_style=False)


def generate_profile(
    intent: Dict[str, Any],
    modules: Sequence[str],
    egress_modules: Sequence[str],
    output_dir: str,
) -> str:
    profile_name = intent["name"]
    output_path = Path(output_dir) / f"{profile_name}.yaml"
    profile = _build_profile_payload(intent, modules, egress_modules)

    header = (
        "# Auto-generated by rSwitch Intent Engine\n"
        f"# Intent: {profile_name}\n"
        f"# Generated: {_generated_timestamp()}\n"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump(profile, f, sort_keys=False, default_flow_style=False)

    return str(output_path)


def generate_module_configs(
    intent: Dict[str, Any], modules: Sequence[str], output_dir: str
) -> List[str]:
    written: List[str] = []
    base_dir = Path(output_dir) / "module_configs"
    base_dir.mkdir(parents=True, exist_ok=True)
    prefix = intent["name"]

    segments = intent.get("segments") or []
    security = intent.get("security", {}) or {}
    qos = intent.get("qos", {}) or {}

    if "vlan" in modules and segments:
        path = base_dir / f"{prefix}_vlan.yaml"
        _write_yaml(path, {"vlan": generate_vlan_config(segments)})
        written.append(str(path))

    if "acl" in modules and security.get("acl"):
        path = base_dir / f"{prefix}_acl.yaml"
        _write_yaml(path, {"acl": generate_acl_config(security)})
        written.append(str(path))

    if "qos_classify" in modules and qos.get("enabled"):
        path = base_dir / f"{prefix}_qos.yaml"
        _write_yaml(path, {"qos": generate_qos_config(qos)})
        written.append(str(path))

    return written


def _format_module_summary(modules: Sequence[str], stage_map: Dict[str, int]) -> str:
    lines = []
    for module in modules:
        stage = stage_map.get(module, "?")
        lines.append(f"  - {module} (stage {stage})")
    return "\n".join(lines)


def _print_summary(
    intent: Dict[str, Any],
    profile_path: str | None,
    module_files: Sequence[str],
    ingress_modules: Sequence[str],
    egress_modules: Sequence[str],
    warnings: Sequence[str],
    dry_run: bool,
) -> None:
    print(f"Intent: {intent['name']}")
    print("Ingress modules:")
    print(_format_module_summary(ingress_modules, MODULE_STAGES))
    print("Egress modules:")
    print(_format_module_summary(egress_modules, EGRESS_MODULES))

    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  - {warning}")

    if dry_run:
        print("Dry-run mode: no files were written")
        if profile_path:
            print(f"Would generate profile: {profile_path}")
        if module_files:
            print("Would generate module configs:")
            for file_path in module_files:
                print(f"  - {file_path}")
        return

    if profile_path:
        print(f"Generated profile: {profile_path}")
    if module_files:
        print("Generated module configs:")
        for file_path in module_files:
            print(f"  - {file_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Translate high-level network intents into rSwitch profiles"
    )
    parser.add_argument("intent_file", help="Path to intent YAML file")
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Directory for generated profile/config outputs (default: current directory)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and resolve intent, but do not write files",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate input intent only and exit",
    )
    args = parser.parse_args()

    try:
        intent = parse_intent(args.intent_file)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    validation = validate_intent(intent)
    if validation.warnings:
        for warning in validation.warnings:
            print(f"WARN: {warning}", file=sys.stderr)

    if args.validate:
        print(f"Intent validation passed: {intent['name']}")
        return 0

    ingress_modules, egress_modules = resolve_modules(intent)

    profile_path = os.path.join(args.output_dir, f"{intent['name']}.yaml")
    module_files_preview = [
        os.path.join(args.output_dir, "module_configs", f"{intent['name']}_vlan.yaml"),
        os.path.join(args.output_dir, "module_configs", f"{intent['name']}_acl.yaml"),
        os.path.join(args.output_dir, "module_configs", f"{intent['name']}_qos.yaml"),
    ]

    if args.dry_run:
        expected_module_files = []
        if "vlan" in ingress_modules and intent.get("segments"):
            expected_module_files.append(module_files_preview[0])
        if "acl" in ingress_modules and (intent.get("security") or {}).get("acl"):
            expected_module_files.append(module_files_preview[1])
        if "qos_classify" in ingress_modules and (intent.get("qos") or {}).get("enabled"):
            expected_module_files.append(module_files_preview[2])

        _print_summary(
            intent,
            profile_path,
            expected_module_files,
            ingress_modules,
            egress_modules,
            validation.warnings,
            dry_run=True,
        )
        return 0

    written_profile = generate_profile(
        intent,
        ingress_modules,
        egress_modules,
        args.output_dir,
    )
    written_module_configs = generate_module_configs(intent, ingress_modules, args.output_dir)

    _print_summary(
        intent,
        written_profile,
        written_module_configs,
        ingress_modules,
        egress_modules,
        validation.warnings,
        dry_run=False,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
