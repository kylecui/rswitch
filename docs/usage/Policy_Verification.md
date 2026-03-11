# Policy Verification

## What It Is

`scripts/policy_verify.py` is an offline verification tool for checking whether an rSwitch profile satisfies a policy contract before deployment.

It performs static analysis only: it reads a policy YAML file plus a profile YAML file, builds a simplified packet-processing model from configured modules and stages, and evaluates policy assertions.

## How To Run

Basic run:

```bash
python3 scripts/policy_verify.py examples/policies/campus_policy.yaml output/campus-edge-switch.yaml
```

Verbose reasoning:

```bash
python3 scripts/policy_verify.py examples/policies/campus_policy.yaml output/campus-edge-switch.yaml --verbose
```

Machine-readable report:

```bash
python3 scripts/policy_verify.py examples/policies/campus_policy.yaml output/campus-edge-switch.yaml --json
```

Exit status is `0` when all assertions pass, `1` when one or more assertions fail, and `2` for input/validation errors.

## Policy YAML Format

```yaml
policy:
  name: "campus-network-policy"
  description: "Verify campus network segmentation and access control"
  assertions:
    - type: reachable
      from: { vlan: 100 }
      to: { vlan: 200 }
      protocol: any
      expect: deny
      description: "Inter-VLAN traffic denied without routing"
```

- `policy.name`: policy identifier for reports
- `policy.description`: optional free-form text
- `policy.assertions`: non-empty list of assertion objects

## Assertion Types

### `reachable`

Checks whether traffic should be allowed or denied.

Selectors:
- `from` / `to`: one of `{ vlan: <id> }`, `{ subnet: "a.b.c.d/prefix" }`, `{ host: "a.b.c.d" }`
- `protocol`: `any`, `<name>` (for example `tcp`), or `{ tcp: 443 }` / `{ udp: 53 }`
- `expect`: `allow` or `deny`

Evaluation model:
- If flow crosses VLAN or subnet boundaries and `route` is not loaded, result is `deny`.
- If `acl` is not loaded, result is `allow`.
- If `acl` is loaded, ACL rules are checked in order of rule `id`; first match wins.
- If no ACL rule matches, ACL default action is used (`config.acl.default_action`, then `config.settings.acl_default_action`, then allow).

### `module_loaded`

Checks whether a module exists in the profile's ingress module list.

```yaml
- type: module_loaded
  module: acl
  expect: true
```

### `stage_order`

Checks module stage ordering using internal stage metadata.

```yaml
- type: stage_order
  before: acl
  after: route
```

### `vlan_exists`

Checks that a VLAN ID is configured (`config.vlan.vlans[].vlan_id` or legacy top-level `vlans[].vlan_id`).

```yaml
- type: vlan_exists
  vlan: 100
```

## Example Output

```text
Policy:  campus-network-policy
Profile: campus-edge-switch
Result:  FAIL (8/10 assertions passed)

[PASS] 01 Same-VLAN traffic should be allowed
[PASS] 02 Inter-VLAN traffic should be denied without routing
[FAIL] 03 HTTPS to server should be allowed
```

## Limitations

- Static analysis only; this does not inspect live dataplane state.
- Verification is based on profile/module configuration and simplified ACL matching, not packet replay.
- Unsupported assertion types are marked as failed.
