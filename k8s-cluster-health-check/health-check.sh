#!/usr/bin/env bash
# Comprehensive Cluster Health Check Script
# Auto-detects and reports issues across all stack components
#
# Usage:
#   1. Copy config.example.sh to config.sh and customize
#   2. Run: ./health-check.sh
#
# Version: 4.0.0 - Configurable refactoring:
#   - All cluster-specific values extracted to config.sh
#   - No hardcoded IPs, hostnames, or paths
#   - Portable across different Kubernetes clusters
#
# Previous versions:
#   3.3.0 - KEDA, Encryption, CronJob Automation checks
#   3.2.0 - Tracing, deception, CNPG, dashboard hub checks
#   3.1.0 - Backend & messaging checks
#   3.0.0 - Modular refactoring (split monolith into modules)

set -uo pipefail
IFS=$'\n\t'
# Note: -e removed to allow script to continue on non-critical failures

# Verify required commands exist
for _cmd in kubectl jq; do
    if ! command -v "$_cmd" &>/dev/null; then
        echo "ERROR: Required command not found: $_cmd" >&2
        exit 1
    fi
done
# Optional commands checked at point of use: talosctl, openssl, curl
unset _cmd

# Get script directory for sourcing modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load user configuration (if exists)
if [[ -f "$SCRIPT_DIR/config.sh" ]]; then
    source "$SCRIPT_DIR/config.sh"
fi

# =============================================================================
# Configuration defaults (override in config.sh)
# =============================================================================

# Cluster access
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
NODES="${NODES:-}"
CLUSTER_NAME="${CLUSTER_NAME:-kubernetes}"

# Network topology
API_VIP="${API_VIP:-}"
API_PORT="${API_PORT:-6443}"
GATEWAY_IP="${GATEWAY_IP:-}"
COREDNS_EXTERNAL_IP="${COREDNS_EXTERNAL_IP:-}"

# OIDC / Identity
KANIDM_IP="${KANIDM_IP:-}"
KANIDM_PORT="${KANIDM_PORT:-443}"
OIDC_PATH="${OIDC_PATH:-/oauth2/openid/kubernetes/.well-known/openid-configuration}"

# Node naming
NODE_HOSTNAMES="${NODE_HOSTNAMES:-}"
ETCD_CHECK_NODE="${ETCD_CHECK_NODE:-}"

# DNS validation
VALID_EXTERNAL_DNS="${VALID_EXTERNAL_DNS:-8.8.8.8 1.1.1.1}"

# Export all config variables for library modules
export KUBECONFIG NODES CLUSTER_NAME
export API_VIP API_PORT GATEWAY_IP COREDNS_EXTERNAL_IP
export KANIDM_IP KANIDM_PORT OIDC_PATH
export NODE_HOSTNAMES ETCD_CHECK_NODE VALID_EXTERNAL_DNS

# =============================================================================
# Source all modules
# =============================================================================

source "$SCRIPT_DIR/lib/helpers.sh"
source "$SCRIPT_DIR/lib/pod-checks.sh"
source "$SCRIPT_DIR/lib/cluster/infrastructure.sh"
source "$SCRIPT_DIR/lib/cluster/storage.sh"
source "$SCRIPT_DIR/lib/security/policies.sh"
source "$SCRIPT_DIR/lib/security/network.sh"
source "$SCRIPT_DIR/lib/security/authentication.sh"
source "$SCRIPT_DIR/lib/observability/monitoring.sh"
source "$SCRIPT_DIR/lib/observability/tracing.sh"
source "$SCRIPT_DIR/lib/security/deception.sh"
source "$SCRIPT_DIR/lib/services/infrastructure.sh"
source "$SCRIPT_DIR/lib/services/backend.sh"

# ============================================================================
# APISIX ETCD CLUSTER HEALTH (kept inline due to complexity)
# ============================================================================

check_apisix_etcd() {
    header "🗃️  APISIX ETCD CLUSTER HEALTH"

    # Check if apisix-etcd pods exist
    local etcd_pods
    etcd_pods=$(kubectl get pods -n apisix -l app.kubernetes.io/name=apisix-etcd --no-headers 2>/dev/null)
    local etcd_running
    etcd_running=$(echo "$etcd_pods" | grep -c "Running" 2>/dev/null || echo "0")
    local etcd_ready
    etcd_ready=$(echo "$etcd_pods" | grep -c " 1/1 " 2>/dev/null || echo "0")
    local etcd_total
    etcd_total=$(echo "$etcd_pods" | wc -l | tr -d ' ')

    # APISIX IC 2.0 runs in standalone mode without etcd
    # Only check etcd health if etcd pods are actually deployed
    if [[ ${etcd_total:-0} -eq 0 ]]; then
        info "APISIX running in standalone mode (no etcd)"
        return 0
    fi

    if [[ $etcd_ready -eq 3 ]]; then
        pass "APISIX etcd cluster: $etcd_ready/3 ready"
    elif [[ $etcd_running -eq $etcd_total && $etcd_total -gt 0 ]]; then
        warn "APISIX etcd cluster: $etcd_ready/$etcd_total ready"
    else
        fail "APISIX etcd cluster: $etcd_ready/$etcd_total ready"
    fi

    # Check etcd cluster health via etcdctl
    subheader "Member Health"
    local healthy_members=0
    for i in 0 1 2; do
        local pod="apisix-etcd-$i"
        local health
        health=$(kubectl exec -n apisix "$pod" -- etcdctl endpoint health --endpoints=http://127.0.0.1:2379 2>&1 | grep -o "is healthy" || true)
        if [[ -n "$health" ]]; then
            pass "$pod: healthy"
            ((healthy_members++))
        else
            fail "$pod: unhealthy or unreachable"
        fi
    done

    # Check quorum status
    subheader "Quorum Status"
    helper_check_quorum "$healthy_members" 3 "APISIX etcd cluster"
}

# ============================================================================
# SUMMARY
# ============================================================================

generate_summary() {
    header "📋 HEALTH CHECK SUMMARY"

    echo ""
    echo "Total checks: $TOTAL_CHECKS"
    echo -e "  ${GREEN}Passed:${NC}   $PASSED_CHECKS"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo -e "  ${RED}Failures:${NC} $FAILURES"
    echo ""

    local health_pct
    health_pct=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))

    if [[ $FAILURES -eq 0 && $WARNINGS -eq 0 ]]; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  CLUSTER HEALTH: EXCELLENT (${health_pct}%)${NC}"
        echo -e "${GREEN}  All components operational${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    elif [[ $FAILURES -eq 0 ]]; then
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  CLUSTER HEALTH: GOOD (${health_pct}%)${NC}"
        echo -e "${YELLOW}  $WARNINGS warnings - review recommended${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    elif [[ $FAILURES -lt 5 ]]; then
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  CLUSTER HEALTH: WARNING (${health_pct}%)${NC}"
        echo -e "${YELLOW}  $FAILURES failures detected - attention required${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    else
        echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}  CLUSTER HEALTH: CRITICAL (${health_pct}%)${NC}"
        echo -e "${RED}  $FAILURES failures detected - immediate action required${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    fi

    echo ""
    echo "Quick investigation commands:"
    echo "  kubectl get pods -A | grep -vE 'Running|Completed'"
    echo "  kubectl get events -A --sort-by='.lastTimestamp' | tail -20"
    echo "  kubectl describe pod <pod> -n <namespace>"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    echo ""
    echo "🏥 Comprehensive Cluster Health Check"
    echo "   Cluster: $CLUSTER_NAME"
    echo "   Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "   Version: 4.0.0 (Configurable)"
    echo ""

    # Core infrastructure
    check_nodes
    check_talos
    check_argocd
    check_cilium
    check_apisix
    check_coredns

    # Storage
    check_longhorn
    check_surrealdb
    check_garage_cluster
    check_local_pv_health

    # Security policies
    check_kyverno
    check_trivy
    check_tetragon
    check_policy_controller
    check_supply_chain_security
    check_policy_reporter

    # Network security
    check_cilium_drops
    check_waf_status
    check_tls13
    check_pdbs

    # Authentication
    check_external_secrets
    check_openbao
    check_spire
    check_oidc
    check_oauth2_proxy

    # Backups & etcd
    check_velero
    check_etcd_health
    check_apisix_etcd

    # CI/CD & services
    check_argocd_repos
    check_argo_workflows
    check_argocd_image_updater
    check_zot
    check_image_presync
    check_step_ca
    check_dnscrypt_proxy
    check_smtp_relay
    check_cnpg
    check_dashboard_hub

    # Backend & Messaging
    check_rabbitmq_operator
    check_rabbitmq_cluster
    check_dn_api
    check_messaging_topology
    check_keda

    # Observability
    check_monitoring
    check_tracing
    check_resourcequotas

    # Security (deception)
    check_deception

    # Summary
    check_pod_summary
    check_events
    generate_summary

    # Exit code based on failures
    if [[ $FAILURES -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
