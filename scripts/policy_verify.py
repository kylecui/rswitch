#!/usr/bin/env python3
"""
rSwitch Policy Verification Engine

Verifies that network policies are correctly enforced by rSwitch configurations.
Models the packet processing pipeline as a decision graph and answers reachability queries.

Usage:
    python3 scripts/policy_verify.py <policy.yaml> <profile.yaml> [--verbose]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml


MODULE_CAPABILITIES = {
    "acl": ["filter", "block", "allow"],
    "vlan": ["segment", "tag", "isolate"],
    "route": ["route", "forward_l3"],
    "conntrack": ["stateful_filter", "track_connections"],
    "nat": ["translate", "masquerade"],
    "source_guard": ["validate_source", "anti_spoof"],
    "dhcp_snoop": ["validate_dhcp", "build_binding_table"],
    "qos_classify": ["classify", "mark"],
    "rate_limiter": ["rate_limit", "police"],
    "stp": ["loop_prevent"],
}

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

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class AssertionResult:
    index: int
    assertion_type: str
    description: str
    passed: bool
    expected: Any
    actual: Any
    reason: str


def parse_policy(path: str) -> Dict[str, Any]:
    data = _load_yaml(path, "Policy")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("Policy file must contain top-level 'policy:' mapping")

    assertions = policy.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise ValueError("policy.assertions must be a non-empty list")

    for idx, assertion in enumerate(assertions):
        pfx = f"policy.assertions[{idx}]"
        if not isinstance(assertion, dict):
            raise ValueError(f"{pfx} must be a mapping")
        if not isinstance(assertion.get("type"), str):
            raise ValueError(f"{pfx}.type must be a string")

    return policy


def parse_profile(path: str) -> Dict[str, Any]:
    profile = _load_yaml(path, "Profile")
    if not isinstance(profile.get("name"), str) or not profile["name"].strip():
        raise ValueError("profile.name is required and must be a non-empty string")

    modules = profile.get("modules")
    ingress = profile.get("ingress")
    if isinstance(modules, list):
        _validate_module_list(modules, "profile.modules")
    elif isinstance(ingress, list):
        _validate_module_list(ingress, "profile.ingress")
        profile["modules"] = ingress
    else:
        raise ValueError("profile.modules must be a list (or legacy profile.ingress)")

    egress_modules = profile.get("egress_modules")
    if egress_modules is not None and not isinstance(egress_modules, list):
        raise ValueError("profile.egress_modules must be a list when provided")

    config = profile.get("config")
    if config is not None and not isinstance(config, dict):
        raise ValueError("profile.config must be a mapping when provided")

    return profile


def build_pipeline_model(profile: Dict[str, Any]) -> Dict[str, Any]:
    modules = list(dict.fromkeys(profile.get("modules", [])))
    ordered = sorted(modules, key=lambda mod: (MODULE_STAGES.get(mod, 999), mod))

    capabilities: Set[str] = set()
    for mod in ordered:
        capabilities.update(MODULE_CAPABILITIES.get(mod, []))

    cfg_raw = profile.get("config")
    cfg: Dict[str, Any] = cfg_raw if isinstance(cfg_raw, dict) else {}
    vlan_raw = cfg.get("vlan")
    vlan_cfg: Dict[str, Any] = vlan_raw if isinstance(vlan_raw, dict) else {}
    acl_raw = cfg.get("acl")
    acl_cfg: Dict[str, Any] = acl_raw if isinstance(acl_raw, dict) else {}

    vlan_ids = _extract_vlan_ids(vlan_cfg, profile)

    return {
        "name": profile.get("name"),
        "modules": ordered,
        "module_set": set(ordered),
        "module_stages": {m: MODULE_STAGES.get(m, 999) for m in ordered},
        "capabilities": sorted(capabilities),
        "config": cfg,
        "acl": acl_cfg,
        "vlan_ids": vlan_ids,
    }


def verify_assertion(assertion: Dict[str, Any], model: Dict[str, Any]) -> Tuple[bool, Any, str]:
    atype = assertion.get("type")

    if atype == "module_loaded":
        module = assertion.get("module")
        expected = bool(assertion.get("expect", True))
        actual = module in model["module_set"]
        reason = f"module '{module}' is {'present' if actual else 'absent'}"
        return actual == expected, actual, reason

    if atype == "stage_order":
        before = assertion.get("before")
        after = assertion.get("after")
        stages = model["module_stages"]
        if before not in stages or after not in stages:
            actual = "missing module"
            return False, actual, "one or both referenced modules are not loaded"
        actual = stages[before] < stages[after]
        reason = f"stage({before})={stages[before]}, stage({after})={stages[after]}"
        return actual, actual, reason

    if atype == "vlan_exists":
        vlan = assertion.get("vlan")
        actual = isinstance(vlan, int) and vlan in model["vlan_ids"]
        reason = f"known VLANs: {sorted(model['vlan_ids'])}"
        return actual, actual, reason

    if atype == "reachable":
        expected = str(assertion.get("expect", "allow")).lower()
        actual, reason = _evaluate_reachability(assertion, model)
        return actual == expected, actual, reason

    return False, "unsupported", f"unsupported assertion type: {atype}"


def run_verification(policy: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
    model = build_pipeline_model(profile)
    assertions = policy.get("assertions", [])

    results: List[AssertionResult] = []
    for idx, assertion in enumerate(assertions, start=1):
        passed, actual, reason = verify_assertion(assertion, model)
        results.append(
            AssertionResult(
                index=idx,
                assertion_type=str(assertion.get("type", "unknown")),
                description=str(assertion.get("description", f"Assertion {idx}")),
                passed=passed,
                expected=assertion.get("expect", True),
                actual=actual,
                reason=reason,
            )
        )

    passed_count = sum(1 for item in results if item.passed)
    total = len(results)

    return {
        "policy_name": policy.get("name", "unnamed-policy"),
        "profile_name": profile.get("name", "unnamed-profile"),
        "passed": passed_count,
        "total": total,
        "failed": total - passed_count,
        "success": passed_count == total,
        "results": results,
    }


def print_report(results: Dict[str, Any], verbose: bool = False) -> None:
    status = "PASS" if results["success"] else "FAIL"
    print(f"Policy:  {results['policy_name']}")
    print(f"Profile: {results['profile_name']}")
    print(f"Result:  {status} ({results['passed']}/{results['total']} assertions passed)")
    print()

    for item in results["results"]:
        marker = "PASS" if item.passed else "FAIL"
        print(f"[{marker}] {item.index:02d} {item.description}")
        if verbose:
            print(f"       type={item.assertion_type} expected={item.expected!r} actual={item.actual!r}")
            print(f"       reason: {item.reason}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify policy assertions against an rSwitch profile")
    parser.add_argument("policy_file", help="Path to policy YAML")
    parser.add_argument("profile_file", help="Path to profile YAML")
    parser.add_argument("--verbose", action="store_true", help="Print per-assertion reasoning")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    args = parser.parse_args()

    try:
        policy = parse_policy(args.policy_file)
        profile = parse_profile(args.profile_file)
        results = run_verification(policy, profile)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "policy_name": results["policy_name"],
            "profile_name": results["profile_name"],
            "passed": results["passed"],
            "total": results["total"],
            "failed": results["failed"],
            "success": results["success"],
            "results": [
                {
                    "index": item.index,
                    "type": item.assertion_type,
                    "description": item.description,
                    "passed": item.passed,
                    "expected": item.expected,
                    "actual": item.actual,
                    "reason": item.reason,
                }
                for item in results["results"]
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(results, verbose=args.verbose)

    return 0 if results["success"] else 1


def _load_yaml(path: str, kind: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f"{kind} file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse {kind.lower()} YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{kind} file must parse to a YAML mapping")
    return data


def _validate_module_list(modules: Sequence[Any], field_name: str) -> None:
    for idx, module in enumerate(modules):
        if not isinstance(module, str) or not module.strip():
            raise ValueError(f"{field_name}[{idx}] must be a non-empty string")


def _extract_vlan_ids(vlan_cfg: Dict[str, Any], profile: Dict[str, Any]) -> Set[int]:
    vlan_ids: Set[int] = set()

    for entry in vlan_cfg.get("vlans", []):
        if isinstance(entry, dict) and isinstance(entry.get("vlan_id"), int):
            vlan_ids.add(entry["vlan_id"])

    for entry in profile.get("vlans", []):
        if isinstance(entry, dict) and isinstance(entry.get("vlan_id"), int):
            vlan_ids.add(entry["vlan_id"])

    return vlan_ids


def _evaluate_reachability(assertion: Dict[str, Any], model: Dict[str, Any]) -> Tuple[str, str]:
    src_raw = assertion.get("from")
    src: Dict[str, Any] = src_raw if isinstance(src_raw, dict) else {}
    dst_raw = assertion.get("to")
    dst: Dict[str, Any] = dst_raw if isinstance(dst_raw, dict) else {}
    proto_name, proto_port = _parse_protocol(assertion.get("protocol", "any"))

    route_present = "route" in model["module_set"]

    src_vlan = src.get("vlan") if isinstance(src.get("vlan"), int) else None
    dst_vlan = dst.get("vlan") if isinstance(dst.get("vlan"), int) else None
    src_net = _selector_network(src)
    dst_net = _selector_network(dst)

    cross_vlan = src_vlan is not None and dst_vlan is not None and src_vlan != dst_vlan
    cross_subnet = src_net is not None and dst_net is not None and src_net != dst_net

    if (cross_vlan or cross_subnet) and not route_present:
        return "deny", "traffic crosses VLAN/subnet boundaries but route module is not loaded"

    if "acl" not in model["module_set"]:
        return "allow", "ACL module not loaded; no filtering is applied"

    acl_raw = model.get("acl")
    acl: Dict[str, Any] = acl_raw if isinstance(acl_raw, dict) else {}
    rules_raw = acl.get("rules")
    rules = rules_raw if isinstance(rules_raw, list) else []

    for rule in sorted(_dict_rules(rules), key=_rule_sort_key):
        if _rule_matches(rule, src, dst, proto_name, proto_port):
            action = _normalize_action(rule.get("action", "allow"))
            reason = f"matched ACL rule id={rule.get('id', '?')} action={action}"
            return action, reason

    cfg_raw = model.get("config")
    cfg: Dict[str, Any] = cfg_raw if isinstance(cfg_raw, dict) else {}
    default_action = _default_acl_action(acl, cfg)
    return default_action, f"no ACL rule matched; default action is {default_action}"


def _parse_protocol(value: Any) -> Tuple[str, Optional[int]]:
    if isinstance(value, str):
        return ("any", None) if value.lower() == "any" else (value.lower(), None)

    if isinstance(value, dict) and len(value) == 1:
        proto, port = next(iter(value.items()))
        if isinstance(proto, str) and isinstance(port, int):
            return proto.lower(), port

    return "any", None


def _selector_network(selector: Dict[str, Any]) -> Optional[IPNetwork]:
    if isinstance(selector.get("subnet"), str):
        try:
            return ipaddress.ip_network(selector["subnet"], strict=False)
        except ValueError:
            return None

    if isinstance(selector.get("host"), str):
        try:
            host = ipaddress.ip_address(selector["host"])
            mask = 32 if host.version == 4 else 128
            return ipaddress.ip_network(f"{host}/{mask}", strict=False)
        except ValueError:
            return None

    return None


def _dict_rules(rules: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rule in rules:
        if isinstance(rule, dict):
            out.append(rule)
    return out


def _rule_sort_key(rule: Dict[str, Any]) -> Tuple[int, int]:
    rule_id = rule.get("id")
    if isinstance(rule_id, int):
        return (0, rule_id)
    return (1, 0)


def _rule_matches(
    rule: Dict[str, Any],
    src: Dict[str, Any],
    dst: Dict[str, Any],
    proto_name: str,
    proto_port: Optional[int],
) -> bool:
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    if not match:
        return False

    if match.get("any") is True:
        return True

    if not _match_protocol(match, proto_name):
        return False
    if not _match_port(match, proto_port):
        return False
    if not _match_endpoint(src, match, "src"):
        return False
    if not _match_endpoint(dst, match, "dst"):
        return False

    return True


def _match_protocol(match: Dict[str, Any], proto_name: str) -> bool:
    if proto_name == "any":
        return True

    candidates = [
        match.get("proto"),
        match.get("protocol"),
        match.get("ip_proto"),
    ]
    values = [str(item).lower() for item in candidates if item is not None]
    if not values:
        return True
    return proto_name in values


def _match_port(match: Dict[str, Any], proto_port: Optional[int]) -> bool:
    if proto_port is None:
        return True

    fields = ("port", "dst_port", "src_port", "tcp", "udp")
    seen: List[int] = []
    for field in fields:
        value = match.get(field)
        if isinstance(value, int):
            seen.append(value)

    if not seen:
        return True
    return proto_port in seen


def _match_endpoint(selector: Dict[str, Any], match: Dict[str, Any], direction: str) -> bool:
    vlan_key = f"{direction}_vlan"
    if isinstance(match.get(vlan_key), int):
        if selector.get("vlan") != match[vlan_key]:
            return False

    ip_key = f"{direction}_ip"
    if isinstance(match.get(ip_key), str):
        if selector.get("host") != match[ip_key]:
            return False

    subnet_key = f"{direction}_subnet"
    if isinstance(match.get(subnet_key), str):
        selector_net = _selector_network(selector)
        try:
            match_net = ipaddress.ip_network(match[subnet_key], strict=False)
        except ValueError:
            return False
        if selector_net is None:
            return False
        if isinstance(selector_net, ipaddress.IPv4Network) and isinstance(match_net, ipaddress.IPv4Network):
            if not selector_net.subnet_of(match_net):
                return False
        elif isinstance(selector_net, ipaddress.IPv6Network) and isinstance(match_net, ipaddress.IPv6Network):
            if not selector_net.subnet_of(match_net):
                return False
        else:
            return False

    return True


def _normalize_action(value: Any) -> str:
    text = str(value).lower()
    if text in {"allow", "permit", "pass"}:
        return "allow"
    if text in {"deny", "drop", "block"}:
        return "deny"
    return "allow"


def _default_acl_action(acl: Dict[str, Any], config: Dict[str, Any]) -> str:
    direct = acl.get("default_action")
    if direct is not None:
        return _normalize_action(direct)

    settings_raw = config.get("settings")
    settings: Dict[str, Any] = settings_raw if isinstance(settings_raw, dict) else {}
    settings_action = settings.get("acl_default_action")
    if settings_action is not None:
        return _normalize_action(settings_action)

    return "allow"


if __name__ == "__main__":
    sys.exit(main())
