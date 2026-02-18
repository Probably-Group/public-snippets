#!/bin/bash
# Authentication health checks
# OIDC, Kanidm, oauth2-proxy, SPIRE

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_oidc() {
    header "🔑 OIDC AUTHENTICATION (KANIDM)"

    # Check Kanidm pod
    subheader "Kanidm Identity Provider"
    helper_check_pods_ready "kanidm" "" "Kanidm pods"

    # Check Kanidm service
    local kanidm_svc
    kanidm_svc=$(kubectl get svc -n kanidm kanidm -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    if [[ -n "$kanidm_svc" ]]; then
        pass "Kanidm service available at $kanidm_svc"
    else
        fail "Kanidm service not found"
    fi

    # Check OIDC endpoint connectivity (using config variables)
    if [[ -n "$KANIDM_IP" ]]; then
        subheader "OIDC Endpoint Connectivity"
        local oidc_response
        oidc_response=$(curl -sk --connect-timeout 5 -w "\n%{http_code}" "https://${KANIDM_IP}${OIDC_PATH}" 2>/dev/null)
        local oidc_body
        oidc_body=$(echo "$oidc_response" | head -n -1)
        local oidc_http_code
        oidc_http_code=$(echo "$oidc_response" | tail -1)

        if [[ "$oidc_body" == *"issuer"* ]]; then
            pass "Kanidm OIDC endpoint accessible at $KANIDM_IP"
        elif [[ "$oidc_http_code" == "200" || "$oidc_http_code" == "404" ]]; then
            # Kanidm is reachable but OAuth2 client 'kubernetes' may not be configured
            warn "Kanidm reachable but OIDC discovery returned: $oidc_body (HTTP $oidc_http_code)"
        else
            fail "Kanidm OIDC endpoint not accessible (HTTP $oidc_http_code)"
        fi
    fi

    # Check Cilium bpf-lb-sock setting
    subheader "Cilium Socket-LB Configuration"
    local bpf_lb_sock
    bpf_lb_sock=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.bpf-lb-sock}' 2>/dev/null || echo "unknown")
    if [[ "$bpf_lb_sock" == "false" ]]; then
        pass "Cilium bpf-lb-sock disabled (prevents OIDC race condition)"
    elif [[ "$bpf_lb_sock" == "true" ]]; then
        fail "Cilium bpf-lb-sock enabled - may cause OIDC failures during boot"
    else
        warn "Cilium bpf-lb-sock setting unknown: $bpf_lb_sock"
    fi

    # Check API server OIDC configuration
    if [[ -n "$NODE_HOSTNAMES" && -n "$CLUSTER_NAME" ]]; then
        subheader "API Server OIDC Configuration"
        local oidc_configured=0
        for node in $NODE_HOSTNAMES; do
            local api_pod="kube-apiserver-${CLUSTER_NAME}-$node"
            local oidc_flags
            oidc_flags=$(kubectl get pod -n kube-system $api_pod -o jsonpath='{.spec.containers[0].command}' 2>/dev/null | grep -c "oidc-issuer-url" || true)
            if [[ ${oidc_flags:-0} -gt 0 ]]; then
                ((oidc_configured++))
            fi
        done

        local node_count
        node_count=$(echo $NODE_HOSTNAMES | wc -w | tr -d ' ')
        if [[ $oidc_configured -eq $node_count ]]; then
            pass "OIDC configured on all $node_count API servers"
        elif [[ $oidc_configured -gt 0 ]]; then
            warn "OIDC configured on $oidc_configured/$node_count API servers"
        else
            fail "OIDC not configured on any API server"
        fi
    fi

    # Check OIDC CA file exists on nodes
    subheader "OIDC CA Certificate"
    for node in $NODES; do
        local ca_exists
        ca_exists=$(talosctl -n $node read /var/local/oidc/ca.crt 2>/dev/null | head -1 || echo "")
        if [[ "$ca_exists" == *"BEGIN CERTIFICATE"* ]]; then
            pass "OIDC CA file present on $node"
        else
            warn "OIDC CA file not found on $node"
        fi
    done

    # Check DNS configuration
    subheader "DNS Configuration (Talos Nameservers)"
    for node in $NODES; do
        local dns_first
        dns_first=$(talosctl -n $node get machineconfig -o yaml 2>/dev/null | grep -A5 "nameservers:" | grep -E "^\s+-" | head -1 | tr -d ' -' || echo "unknown")

        # Check against valid external DNS servers
        local dns_valid=false
        for valid_dns in $VALID_EXTERNAL_DNS; do
            if [[ "$dns_first" == "$valid_dns" ]]; then
                dns_valid=true
                break
            fi
        done

        if [[ "$dns_valid" == "true" ]]; then
            pass "External DNS first in nameservers on $node ($dns_first)"
        elif [[ -n "$COREDNS_EXTERNAL_IP" && "$dns_first" == "$COREDNS_EXTERNAL_IP" ]]; then
            fail "CRITICAL: Cluster CoreDNS in nameservers on $node - causes circular dependency!"
        else
            warn "DNS on $node: first=$dns_first (check VALID_EXTERNAL_DNS in config)"
        fi
    done
}

check_oauth2_proxy() {
    header "🔑 OAUTH2-PROXY AUTHENTICATION"

    helper_check_pods_ready "oauth2-proxy" "" "oauth2-proxy pods"
    helper_check_service "oauth2-proxy" "oauth2-proxy" "oauth2-proxy"

    # Check OIDC provider connectivity (via logs)
    subheader "OIDC Provider Connectivity"
    local oidc_errors
    oidc_errors=$(kubectl logs -n oauth2-proxy -l app.kubernetes.io/name=oauth2-proxy --tail=50 2>/dev/null | \
        grep -ci "oidc.*error\|provider.*failed\|could not get jwks" || true)

    if [[ ${oidc_errors:-0} -gt 0 ]]; then
        warn "OIDC provider errors in logs: $oidc_errors"
    else
        pass "No OIDC provider errors in recent logs"
    fi
}

check_spire() {
    header "🔐 SPIRE WORKLOAD IDENTITY & mTLS"

    # Check SPIRE server
    local server_ready
    server_ready=$(kubectl get pods -n spire -l app.kubernetes.io/name=server --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${server_ready:-0} -gt 0 ]]; then
        pass "SPIRE server running"
    else
        fail "SPIRE server not running"
    fi

    # Check SPIRE agent
    helper_check_pods_ready "spire" "app.kubernetes.io/name=agent" "SPIRE agents"

    # Check SPIFFE CSI driver
    local csi_ready
    csi_ready=$(kubectl get pods -n spire -l app.kubernetes.io/name=spiffe-csi-driver --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${csi_ready:-0} -gt 0 ]]; then
        pass "SPIFFE CSI driver running"
    else
        warn "SPIFFE CSI driver not running"
    fi

    # Check ClusterSPIFFEID registrations
    subheader "Workload Registrations"
    local cspiffeid_count
    cspiffeid_count=$(kubectl get clusterspiffeid --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${cspiffeid_count:-0} -ge 20 ]]; then
        pass "ClusterSPIFFEID registrations: $cspiffeid_count (custom + chart defaults)"
    elif [[ ${cspiffeid_count:-0} -gt 0 ]]; then
        warn "ClusterSPIFFEID registrations: $cspiffeid_count (expected 20+)"
    else
        warn "No ClusterSPIFFEID registrations found"
    fi

    # Check SPIRE registration entry count via server
    if [[ ${server_ready:-0} -gt 0 ]]; then
        local entry_count
        entry_count=$(kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry count 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "0")
        if [[ ${entry_count:-0} -gt 0 ]]; then
            pass "SPIRE server has $entry_count registration entries"
        else
            warn "SPIRE server has 0 registration entries"
        fi
    fi

    # Check Cilium-SPIRE integration
    subheader "Cilium-SPIRE Integration"
    local spire_enabled
    spire_enabled=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.mesh-auth-spire-agent-socket}' 2>/dev/null || echo "")
    if [[ -n "$spire_enabled" ]]; then
        pass "Cilium SPIRE integration configured (socket: $spire_enabled)"
    else
        local mesh_auth
        mesh_auth=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.mesh-auth-enabled}' 2>/dev/null || echo "")
        if [[ "$mesh_auth" == "true" ]]; then
            warn "Cilium mesh-auth enabled but SPIRE socket not configured"
        else
            info "Cilium SPIRE mutual auth not yet configured"
        fi
    fi

    # Check Cilium auth metrics (failures)
    subheader "Cilium mTLS Auth Status"
    local auth_failures
    auth_failures=$(kubectl exec -n kube-system ds/cilium -c cilium-agent -- cilium-dbg metrics list 2>/dev/null | grep "cilium_auth_failures_total" | grep -oE '[0-9]+' | head -1 || echo "0")
    if [[ ${auth_failures:-0} -eq 0 ]]; then
        pass "Cilium auth failures: 0"
    else
        warn "Cilium auth failures detected: $auth_failures"
    fi

    # Check Cilium mutual auth status
    subheader "mTLS Status"
    local mesh_auth_enabled
    mesh_auth_enabled=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.mesh-auth-enabled}' 2>/dev/null || echo "")
    if [[ "$mesh_auth_enabled" == "true" ]]; then
        pass "Transparent mTLS active (Cilium mutual auth enabled)"
    else
        info "Cilium mutual auth not enabled — mTLS inactive"
    fi
}

check_external_secrets() {
    header "🔐 EXTERNAL SECRETS OPERATOR"

    local eso_ready
    eso_ready=$(kubectl get pods -n external-secrets --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $eso_ready -ge 3 ]]; then
        pass "External Secrets pods: $eso_ready running"
    else
        warn "External Secrets pods: $eso_ready running"
    fi

    # Check CRD versions
    local crd_versions
    crd_versions=$(kubectl get crd externalsecrets.external-secrets.io -o jsonpath='{.spec.versions[*].name}' 2>/dev/null || echo "")
    if [[ "$crd_versions" == *"v1"* ]]; then
        pass "ExternalSecret CRD has v1 API"
    else
        fail "ExternalSecret CRD missing v1 API (has: $crd_versions)"
    fi

    # Check ExternalSecrets sync status
    local ext_secrets
    ext_secrets=$(kubectl get externalsecrets -A -o json 2>/dev/null)
    local total_es
    total_es=$(echo "$ext_secrets" | jq '.items | length')
    local synced_es
    synced_es=$(echo "$ext_secrets" | jq '[.items[] | select(.status.conditions[]?.type=="Ready" and .status.conditions[]?.status=="True")] | length')

    if [[ $total_es -gt 0 ]]; then
        if [[ $synced_es -eq $total_es ]]; then
            pass "All $total_es ExternalSecrets synced"
        else
            warn "ExternalSecrets: $synced_es/$total_es synced"
        fi
    else
        info "No ExternalSecrets configured"
    fi
}

check_openbao() {
    header "🔑 OPENBAO SECRETS MANAGER"

    # Check OpenBao pods (HA cluster with 3 replicas)
    local openbao_pods
    openbao_pods=$(kubectl get pods -n openbao -l app.kubernetes.io/name=openbao --no-headers 2>/dev/null)
    local openbao_running
    openbao_running=$(echo "$openbao_pods" | grep -c "Running" 2>/dev/null || echo "0")
    local openbao_ready
    openbao_ready=$(echo "$openbao_pods" | grep -c " 1/1 " 2>/dev/null || echo "0")

    if [[ ${openbao_ready:-0} -eq 3 ]]; then
        pass "OpenBao cluster: 3/3 pods ready"
    elif [[ ${openbao_running:-0} -gt 0 ]]; then
        warn "OpenBao cluster: $openbao_ready/3 pods ready"
    else
        fail "OpenBao cluster not running"
    fi

    # Check seal status
    subheader "Seal Status"
    local unsealed_count=0
    for i in 0 1 2; do
        local pod="openbao-$i"
        local seal_status
        seal_status=$(kubectl exec -n openbao "$pod" -- bao status -format=json 2>/dev/null | jq -r '.sealed' 2>/dev/null || echo "unknown")
        if [[ "$seal_status" == "false" ]]; then
            pass "$pod: unsealed"
            ((unsealed_count++))
        elif [[ "$seal_status" == "true" ]]; then
            fail "$pod: SEALED - needs manual unseal"
        else
            warn "$pod: status unknown"
        fi
    done

    # Check quorum (need 2/3 for HA)
    helper_check_quorum "$unsealed_count" 3 "OpenBao cluster"

    # Check ClusterSecretStore connectivity
    subheader "ClusterSecretStore Status"
    local css_status
    css_status=$(kubectl get clustersecretstore openbao -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "unknown")
    if [[ "$css_status" == "True" ]]; then
        pass "ClusterSecretStore 'openbao' is Ready"
    else
        fail "ClusterSecretStore 'openbao' not ready: $css_status"
    fi

    helper_check_crashloop "openbao" "check network policy and unseal status"

    # Check encryption key backups in OpenBao
    subheader "Encryption Key Backups"

    # Check etcd secretbox encryption is active
    if [[ -n "$NODE_HOSTNAMES" && -n "$CLUSTER_NAME" ]]; then
        local secretbox_active=0
        for node in $NODE_HOSTNAMES; do
            local api_pod="kube-apiserver-${CLUSTER_NAME}-$node"
            local enc_flags
            enc_flags=$(kubectl get pod -n kube-system "$api_pod" -o jsonpath='{.spec.containers[0].command}' 2>/dev/null | grep -c "encryption-provider-config" || true)
            if [[ ${enc_flags:-0} -gt 0 ]]; then
                ((secretbox_active++))
            fi
        done
        local node_count
        node_count=$(echo $NODE_HOSTNAMES | wc -w | tr -d ' ')
        if [[ $secretbox_active -eq $node_count ]]; then
            pass "etcd encryption active on all $node_count API servers"
        elif [[ $secretbox_active -gt 0 ]]; then
            warn "etcd encryption active on $secretbox_active/$node_count API servers"
        else
            warn "etcd encryption not detected on API servers"
        fi
    fi

    # Check Longhorn crypto secret exists
    local crypto_secret
    crypto_secret=$(kubectl get secret -n longhorn-system longhorn-crypto --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${crypto_secret:-0} -gt 0 ]]; then
        pass "Longhorn crypto secret exists in longhorn-system"
    else
        warn "Longhorn crypto secret missing in longhorn-system"
    fi

    info "Manual verification: bao kv get secret/bootstrap-secrets/ETCD_SECRETBOX_KEY"
    info "Manual verification: bao kv get secret/bootstrap-secrets/LONGHORN_CRYPTO_KEY"
}
