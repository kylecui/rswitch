#!/bin/bash
# rSwitch Management Daemon Startup Wrapper
#
# Waits briefly for the loader to create the management namespace,
# then launches mgmtd inside it.  Falls back to root-namespace
# execution if the namespace is not ready (mgmtd will create the
# namespace itself and setns() into it before binding the HTTP
# listener).

set -e

RSWITCH_HOME="${RSWITCH_HOME:-/opt/rswitch}"
RSWITCH_PROFILE="${RSWITCH_PROFILE:-all-modules-test.yaml}"
NS_NAME="${MGMT_NAMESPACE:-rswitch-mgmt}"
WAIT_TIMEOUT="${MGMT_NS_TIMEOUT:-10}"
MGMTD_BIN="${RSWITCH_HOME}/build/rswitch-mgmtd"
PROFILE_PATH="${RSWITCH_HOME}/etc/profiles/${RSWITCH_PROFILE}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] MGMTD-START: $1"; }

if [ ! -x "$MGMTD_BIN" ]; then
    log "ERROR: mgmtd binary not found: $MGMTD_BIN"
    exit 1
fi

if [ ! -f "$PROFILE_PATH" ]; then
    log "ERROR: profile not found: $PROFILE_PATH"
    exit 1
fi

# Wait briefly for the loader to create the management namespace.
log "Waiting up to ${WAIT_TIMEOUT}s for namespace '${NS_NAME}'..."
elapsed=0
while [ $elapsed -lt "$WAIT_TIMEOUT" ]; do
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        log "Namespace '${NS_NAME}' found after ${elapsed}s"
        for i in $(seq 1 10); do
            if ip netns exec "$NS_NAME" ip link show mgmt0 2>/dev/null | grep -q 'state UP'; then
                log "Interface mgmt0 is UP in namespace"
                break
            fi
            sleep 1
        done
        log "Launching mgmtd inside namespace '${NS_NAME}'"
        exec nsenter --net=/run/netns/"$NS_NAME" "$MGMTD_BIN" -f "$PROFILE_PATH" -n
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

# Namespace not ready — launch mgmtd in root namespace.
# mgmtd will create the namespace and setns() into it before
# binding the HTTP listener.
log "Namespace '${NS_NAME}' not found after ${WAIT_TIMEOUT}s"
log "Launching mgmtd in root namespace (self-managed mode)"
exec "$MGMTD_BIN" -f "$PROFILE_PATH" -n
