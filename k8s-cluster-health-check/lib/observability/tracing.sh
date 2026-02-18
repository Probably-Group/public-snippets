#!/bin/bash
# Distributed tracing health checks
# Tempo (distributed mode) + OTel Collector DaemonSet

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_tracing() {
    header "🔍 DISTRIBUTED TRACING (Tempo + OTel Collector)"

    # OTel Collector DaemonSet (3 pods, one per node)
    subheader "OTel Collector DaemonSet"
    local otel_ready
    otel_ready=$(kubectl get pods -n tracing -l app.kubernetes.io/name=opentelemetry-collector --no-headers 2>/dev/null | grep -c "Running" || true)
    local otel_total
    otel_total=$(kubectl get pods -n tracing -l app.kubernetes.io/name=opentelemetry-collector --no-headers 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ ${otel_ready:-0} -eq 3 ]]; then
        pass "OTel Collector DaemonSet: $otel_ready/3 running"
    elif [[ ${otel_ready:-0} -gt 0 ]]; then
        warn "OTel Collector DaemonSet: $otel_ready/$otel_total running (expected 3)"
    else
        fail "OTel Collector DaemonSet: 0 pods running"
    fi

    # Tempo components (distributed mode)
    subheader "Tempo Components"
    local tempo_components=("distributor" "ingester" "querier" "query-frontend" "compactor")
    local tempo_healthy=0

    for component in "${tempo_components[@]}"; do
        local comp_ready
        comp_ready=$(kubectl get pods -n tracing -l app.kubernetes.io/component="$component" --no-headers 2>/dev/null | grep -c "Running" || true)
        if [[ ${comp_ready:-0} -gt 0 ]]; then
            pass "Tempo $component: running"
            ((tempo_healthy++))
        else
            fail "Tempo $component: not running"
        fi
    done

    if [[ $tempo_healthy -eq 5 ]]; then
        pass "All 5 Tempo components healthy"
    else
        warn "Tempo components healthy: $tempo_healthy/5"
    fi

    # Tempo ingester WAL disk usage
    subheader "Ingester WAL Storage"
    local ingester_pod
    ingester_pod=$(kubectl get pods -n tracing -l app.kubernetes.io/component=ingester -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$ingester_pod" ]]; then
        local wal_usage
        wal_usage=$(kubectl exec -n tracing "$ingester_pod" -- df /var/tempo 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
        if [[ -n "$wal_usage" ]]; then
            if [[ ${wal_usage:-0} -gt 85 ]]; then
                fail "Ingester WAL disk usage: ${wal_usage}% (>85%)"
            elif [[ ${wal_usage:-0} -gt 70 ]]; then
                warn "Ingester WAL disk usage: ${wal_usage}%"
            else
                pass "Ingester WAL disk usage: ${wal_usage}%"
            fi
        else
            info "Could not check ingester WAL disk usage"
        fi
    fi

    # OTel Collector metrics pipeline (prometheus exporter on port 8889)
    subheader "OTel Metrics Pipeline"
    local otel_pod
    otel_pod=$(kubectl get pods -n tracing -l app.kubernetes.io/name=opentelemetry-collector -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$otel_pod" ]]; then
        local metrics_port
        metrics_port=$(kubectl get pod -n tracing "$otel_pod" -o json 2>/dev/null | jq -r '.spec.containers[0].ports[]? | select(.containerPort==8889) | .containerPort' 2>/dev/null || echo "")
        if [[ "$metrics_port" == "8889" ]]; then
            pass "OTel Collector prometheus exporter port 8889 configured"
        else
            warn "OTel Collector prometheus exporter port 8889 not found"
        fi
    fi

    # S3 credentials secret
    subheader "S3 Backend"
    local s3_secret
    s3_secret=$(kubectl get secret -n tracing tempo-s3-credentials --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${s3_secret:-0} -gt 0 ]]; then
        pass "S3 credentials secret exists (tempo-s3-credentials)"
    else
        fail "S3 credentials secret missing (tempo-s3-credentials)"
    fi
}
