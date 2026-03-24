> **⚠️ ARCHIVED** — This document is historical reference only. It may not reflect current implementation. See [current documentation](../README.md) for up-to-date information.

# Scenario-based Profiles

Profiles live under `rswitch/etc/profiles/`. Profiles are YAML files that describe
which modules run at each hook/stage and provide configuration values for
module-specific behavior.

Common profiles (examples included in the repository)
- `dumb.yaml` — simple flooding switch (L2 test)
- `l2.yaml` — L2 learning, VLAN, and basic forwarding
- `l3.yaml` — L3 routing with basic ACL
- `firewall.yaml` — security-focused, ordered ACLs
- `l3-qos-voqd-test.yaml` — L3 routing with QoS + VOQd integration for performance testing
- `qos-voqd-test.yaml` — QoS heavy scenario with VOQd
- `vlan-isolation.yaml` — VLAN isolation scenario

Selecting a profile
```
PROFILE=etc/profiles/l3-qos-voqd-test.yaml
sudo ./build/rswitch_loader --profile "$PROFILE" --ifaces ens34,ens35
```

Custom profile example
```
name: my-custom-switch
ingress:
  - vlan
  - l2learn
  - acl
  - lastcall
egress:
  - qos
  - voqd
  - egress_final

# NOTE: Advanced YAML features like module sub-fields (required, stage overrides)
# and optional_modules are planned but not yet implemented.
# The config section shown above is supported and used in production.

Best practices
- Keep module ordering intentional; avoid duplicate stage numbers that conflict
- Limit the number of per-packet heavy modules (e.g., deep inspection) on fast
  paths to preserve performance
- Use `rswitch/user/tools/*.sh` scripts to validate and sanity-check profile behavior
- For VOQd + AF_XDP: set appropriate CPU affinity and ensure UMEM/AF_XDP socket creation
  is successful (see `rswitch/scripts/rswitch_start.sh` and `rswitch/user/voqd`) 
