#!/bin/bash
# Observability health checks
# VictoriaMetrics, Grafana, Alertmanager, VictoriaLogs, Vector

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

# Colors for alerts
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_monitoring() {
    header "📊 MONITORING STACK"

    # VictoriaMetrics
    subheader "VictoriaMetrics"
    helper_check_pods_ready "monitoring" "app.kubernetes.io/name=vmsingle" "VictoriaMetrics single"
    helper_check_pods_ready "monitoring" "app.kubernetes.io/name=vmagent" "VMAgent"

    # Grafana
    subheader "Grafana"
    helper_check_pods_ready "monitoring" "app.kubernetes.io/name=grafana" "Grafana"

    # Alertmanager
    local alertmanager
    alertmanager=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=vmalertmanager --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${alertmanager:-0} -gt 0 ]]; then
        pass "VMAlertmanager running"
    else
        warn "VMAlertmanager not running"
    fi

    # VictoriaLogs
    subheader "Logging"
    local vl_ready
    vl_ready=$(kubectl get pods -n victorialogs --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $vl_ready -gt 0 ]]; then
        pass "VictoriaLogs running"
    else
        warn "VictoriaLogs not running"
    fi

    # Vector
    helper_check_pods_ready "vector" "" "Vector agents"

    # Check feature health alerts VMRule
    subheader "Feature Health Alerts"
    local feature_alerts_rule
    feature_alerts_rule=$(kubectl get vmrule -n monitoring feature-health-alerts --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${feature_alerts_rule:-0} -gt 0 ]]; then
        pass "Feature health alerts VMRule deployed"
    else
        warn "Feature health alerts VMRule missing (feature-health-alerts)"
    fi

    # Check VMAlert firing alerts
    subheader "Alert Status"
    local alert_pod
    alert_pod=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=vmalertmanager -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [[ -n "$alert_pod" ]]; then
        local critical_alerts
        critical_alerts=$(kubectl exec -n monitoring $alert_pod -c alertmanager -- wget -qO- http://localhost:9093/api/v2/alerts 2>/dev/null | jq '[.[] | select(.status.state=="active" and (.labels.severity=="critical" or .labels.severity=="error"))] | length' 2>/dev/null || echo "0")
        local warning_alerts
        warning_alerts=$(kubectl exec -n monitoring $alert_pod -c alertmanager -- wget -qO- http://localhost:9093/api/v2/alerts 2>/dev/null | jq '[.[] | select(.status.state=="active" and .labels.severity=="warning")] | length' 2>/dev/null || echo "0")

        if [[ ${critical_alerts:-0} -gt 0 ]]; then
            fail "Critical alerts firing: $critical_alerts"
        else
            pass "No critical alerts firing"
        fi

        if [[ ${warning_alerts:-0} -gt 5 ]]; then
            warn "Warning alerts firing: $warning_alerts"
        else
            info "Warning alerts: ${warning_alerts:-0}"
        fi

        # List active alerts
        local active_alerts
        active_alerts=$(kubectl exec -n monitoring $alert_pod -c alertmanager -- wget -qO- 'http://localhost:9093/api/v2/alerts?silenced=false&inhibited=false' 2>/dev/null | \
            jq -r '.[] | select(.labels.alertname != "InfoInhibitor" and .labels.alertname != "DiscordIntegrationTest" and .labels.alertname != "Watchdog") | "\(.labels.severity)\t\(.labels.alertname)\t\(.annotations.summary // .annotations.description // "no description")"' 2>/dev/null | \
            sort | uniq)

        if [[ -n "$active_alerts" ]]; then
            subheader "Active Alerts (Unresolved)"
            echo "$active_alerts" | while IFS=$'\t' read -r severity alertname summary; do
                case "$severity" in
                    critical|error) echo -e "    ${RED}●${NC} [$severity] $alertname: $summary" ;;
                    warning) echo -e "    ${YELLOW}●${NC} [$severity] $alertname: $summary" ;;
                    *) echo -e "    ${BLUE}●${NC} [$severity] $alertname: $summary" ;;
                esac
            done
        fi
    else
        warn "VMAlertmanager not found - cannot check alerts"
    fi
}

check_resourcequotas() {
    header "📊 RESOURCE QUOTA USAGE"

    # Get all ResourceQuotas with usage
    local quotas
    quotas=$(kubectl get resourcequota -A -o json 2>/dev/null)
    local total_quotas
    total_quotas=$(echo "$quotas" | jq '.items | length')

    if [[ ${total_quotas:-0} -eq 0 ]]; then
        info "No ResourceQuotas configured"
        return
    fi

    info "Total ResourceQuotas: $total_quotas"
    pass "ResourceQuota check complete"
}

check_pod_summary() {
    header "🐳 POD HEALTH SUMMARY"

    local total_pods
    total_pods=$(kubectl get pods -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local running_pods
    running_pods=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c "Running" || true)
    local completed_pods
    completed_pods=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c "Completed" || true)
    local pending_pods
    pending_pods=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c "Pending" || true)
    local failed_pods
    failed_pods=$(kubectl get pods -A --no-headers 2>/dev/null | grep -cE "Error|CrashLoopBackOff|ImagePullBackOff" || true)

    info "Total pods: $total_pods"
    pass "Running: $running_pods"

    if [[ ${completed_pods:-0} -gt 0 ]]; then
        info "Completed: $completed_pods"
    fi

    if [[ ${pending_pods:-0} -gt 0 ]]; then
        warn "Pending: $pending_pods"
        kubectl get pods -A --no-headers 2>/dev/null | grep "Pending" | head -5 | while read line; do
            echo "    $line"
        done
    fi

    if [[ $failed_pods -gt 0 ]]; then
        fail "Failed/CrashLoop: $failed_pods"
        kubectl get pods -A --no-headers 2>/dev/null | grep -E "Error|CrashLoopBackOff|ImagePullBackOff" | head -5 | while read line; do
            echo "    $line"
        done
    fi

    # Check for pods with high restart counts
    subheader "High Restart Counts"
    local high_restarts
    high_restarts=$(kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.status.containerStatuses[]?.restartCount > 5) | "\(.metadata.namespace)/\(.metadata.name): \(.status.containerStatuses[0].restartCount) restarts"')
    if [[ -n "$high_restarts" ]]; then
        warn "Pods with high restart counts:"
        echo "$high_restarts" | while read line; do
            echo "    $line"
        done
    else
        pass "No pods with high restart counts"
    fi
}

check_events() {
    header "📜 RECENT WARNING EVENTS"

    local warning_events
    warning_events=$(kubectl get events -A --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -10)
    if [[ -n "$warning_events" ]]; then
        warn "Recent warning events:"
        echo "$warning_events" | while read line; do
            echo "  $line"
        done
    else
        pass "No recent warning events"
    fi
}
