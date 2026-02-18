#!/bin/bash
# Deception infrastructure health checks
# Tarpit, honeypot, scanner-confuser, fingerprint-collector, valkey-blocklist

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_deception() {
    header "🎭 DECEPTION INFRASTRUCTURE"

    # Check if namespace exists
    local ns_exists
    ns_exists=$(kubectl get namespace deception --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${ns_exists:-0} -eq 0 ]]; then
        info "Deception namespace not deployed"
        return 0
    fi

    # Check each deception component
    subheader "Deception Components"
    local deception_components=("fingerprint-collector" "honeypot-api" "scanner-confuser" "tarpit")
    local components_healthy=0

    for component in "${deception_components[@]}"; do
        local comp_ready
        comp_ready=$(kubectl get pods -n deception -l app.kubernetes.io/name="$component" --no-headers 2>/dev/null | grep -c "Running" || true)
        if [[ ${comp_ready:-0} -gt 0 ]]; then
            pass "$component: running"
            ((components_healthy++))
        else
            fail "$component: not running"
        fi
    done

    if [[ $components_healthy -eq 4 ]]; then
        pass "All 4 deception components healthy"
    else
        warn "Deception components healthy: $components_healthy/4"
    fi

    # Valkey blocklist (critical for scanner gate)
    subheader "Valkey Blocklist"
    local valkey_ready
    valkey_ready=$(kubectl get pods -n deception -l app.kubernetes.io/name=valkey-blocklist --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${valkey_ready:-0} -gt 0 ]]; then
        pass "Valkey blocklist running (scanner gate dependency)"
    else
        fail "Valkey blocklist not running (scanner gate broken!)"
    fi

    # Verify network isolation (deception must have zero egress)
    subheader "Network Isolation"
    local netpol_count
    netpol_count=$(kubectl get ciliumnetworkpolicy -n deception --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${netpol_count:-0} -gt 0 ]]; then
        pass "Network policies present in deception namespace ($netpol_count policies)"
    else
        fail "No network policies in deception namespace (zero-egress not enforced!)"
    fi
}
