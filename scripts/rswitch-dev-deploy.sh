#!/bin/bash
# rswitch-dev-deploy.sh
# Dev-mode automatic deployment with grace period.
# Waits GRACE_PERIOD before pulling from git and rebuilding.

set -euo pipefail

GRACE_PERIOD="${GRACE_PERIOD:-60}"
RSWITCH_REPO="${RSWITCH_REPO:-/opt/rswitch-src}"
RSWITCH_BRANCH="${RSWITCH_BRANCH:-dev}"
AUTO_START="${AUTO_START:-true}"
DEV_DEPLOY_LOG="${DEV_DEPLOY_LOG:-/var/log/rswitch/dev-deploy.log}"

log() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] DEV-DEPLOY: $*" | tee -a "$DEV_DEPLOY_LOG" 2>/dev/null || echo "[$ts] DEV-DEPLOY: $*"
}

ensure_dirs() {
    mkdir -p /var/log/rswitch 2>/dev/null || true
}

load_config() {
    if [ -f /etc/rswitch/dev-deploy.conf ]; then
        # shellcheck source=/dev/null
        source /etc/rswitch/dev-deploy.conf
        log "Loaded config from /etc/rswitch/dev-deploy.conf"
    else
        log "No config file found, using defaults"
    fi
}

do_deploy() {
    ensure_dirs
    load_config

    log "=========================================="
    log "Dev deployment starting"
    log "=========================================="
    log "Grace period: ${GRACE_PERIOD}s"
    log "Repository: $RSWITCH_REPO"
    log "Branch: $RSWITCH_BRANCH"
    log "Auto-start: $AUTO_START"

    if [ ! -d "$RSWITCH_REPO" ]; then
        log "ERROR: Repository directory not found: $RSWITCH_REPO"
        exit 1
    fi

    log "Waiting grace period ($GRACE_PERIOD seconds)"
    for ((i = 1; i <= GRACE_PERIOD; i++)); do
        echo -ne "\r[$((GRACE_PERIOD - i + 1))s remaining...]" >&2
        sleep 1
    done
    echo "" >&2

    log "Entering repository: $RSWITCH_REPO"
    cd "$RSWITCH_REPO"

    log "Fetching from origin"
    if ! git fetch origin >> "$DEV_DEPLOY_LOG" 2>&1; then
        log "ERROR: git fetch failed"
        exit 1
    fi

    log "Checking out branch: $RSWITCH_BRANCH"
    if ! git checkout "$RSWITCH_BRANCH" >> "$DEV_DEPLOY_LOG" 2>&1; then
        log "ERROR: git checkout failed"
        exit 1
    fi

    log "Pulling latest changes"
    if ! git pull >> "$DEV_DEPLOY_LOG" 2>&1; then
        log "ERROR: git pull failed"
        exit 1
    fi

    log "Running make clean"
    if ! make clean >> "$DEV_DEPLOY_LOG" 2>&1; then
        log "ERROR: make clean failed"
        exit 1
    fi

    log "Running make"
    if ! make >> "$DEV_DEPLOY_LOG" 2>&1; then
        log "ERROR: Build failed"
        log "=========================================="
        exit 1
    fi

    log "Build succeeded"

    if [ "$AUTO_START" = "true" ]; then
        log "Starting rswitch service"
        if systemctl start rswitch; then
            log "rswitch service started successfully"
        else
            log "WARNING: Failed to start rswitch service"
        fi
    else
        log "Auto-start disabled, manual start required"
    fi

    log "Dev deployment complete"
    log "=========================================="
}

do_deploy
