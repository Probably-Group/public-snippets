#!/bin/bash
# Network security health checks
# Cilium policy drops, WAF status, TLS enforcement

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
fi

check_cilium_drops() {
    header "🚫 CILIUM NETWORK POLICY DROPS"

    # Get recent policy drops (last 100 flows)
    local drops
    drops=$(kubectl exec -n kube-system ds/cilium -c cilium-agent -- \
        hubble observe --verdict DROPPED --last 100 -o json 2>/dev/null | \
        jq -r 'select(.drop_reason_desc) | .drop_reason_desc' | sort | uniq -c | sort -rn)

    if [[ -z "$drops" ]]; then
        pass "No recent policy drops detected"
    else
        subheader "Drop Reasons (last 100 flows)"
        local policy_denied
        policy_denied=$(echo "$drops" | grep -i "policy denied" | awk '{print $1}' || echo "0")
        local vlan_drops
        vlan_drops=$(echo "$drops" | grep -i "vlan" | awk '{print $1}' || echo "0")
        local l3_drops
        l3_drops=$(echo "$drops" | grep -i "unsupported L3" | awk '{print $1}' || echo "0")

        # Policy denied is the important one
        if [[ ${policy_denied:-0} -gt 10 ]]; then
            warn "Policy denied drops: $policy_denied (may need network policy fixes)"
        elif [[ ${policy_denied:-0} -gt 0 ]]; then
            info "Policy denied drops: $policy_denied"
        else
            pass "No policy denied drops"
        fi

        # These are usually noise
        if [[ ${vlan_drops:-0} -gt 0 ]]; then
            info "VLAN drops (L2 noise): $vlan_drops"
        fi
        if [[ ${l3_drops:-0} -gt 0 ]]; then
            info "Unsupported L3 drops (IPv6): $l3_drops"
        fi
    fi

    # Check for specific namespace drops
    subheader "Recent Drops by Namespace"
    local ns_drops
    ns_drops=$(kubectl exec -n kube-system ds/cilium -c cilium-agent -- \
        hubble observe --verdict DROPPED --last 50 -o json 2>/dev/null | \
        jq -r 'select(.drop_reason_desc == "Policy denied") | .destination.namespace // "unknown"' | \
        sort | uniq -c | sort -rn | head -5)

    if [[ -n "$ns_drops" ]]; then
        echo "$ns_drops" | while read count ns; do
            if [[ ${count:-0} -gt 5 ]]; then
                warn "  $ns: $count policy denials"
            else
                info "  $ns: $count policy denials"
            fi
        done
    else
        pass "No namespace-specific policy denials"
    fi
}

check_waf_status() {
    header "🛡️  WEB APPLICATION FIREWALL (CORAZA)"

    # Check WASM plugin on APISIX pods
    subheader "WASM Plugin Configuration"
    local apisix_pods
    apisix_pods=$(kubectl get pods -n apisix -l app.kubernetes.io/name=apisix -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    local total_pods
    total_pods=$(echo "$apisix_pods" | wc -w | tr -d ' ')

    if [[ ${total_pods:-0} -eq 0 ]]; then
        fail "No APISIX pods found"
        return
    fi

    # Check WASM file on ALL pods
    local wasm_ok=0
    local wasm_missing=0
    for pod in $apisix_pods; do
        local wasm_exists
        wasm_exists=$(kubectl exec -n apisix "$pod" -c apisix -- ls -la /usr/local/apisix/proxywasm/coraza-proxy-wasm.wasm 2>/dev/null | wc -l | tr -d ' ')
        if [[ ${wasm_exists:-0} -gt 0 ]]; then
            ((wasm_ok++))
        else
            ((wasm_missing++))
            warn "WASM plugin missing on pod: $pod"
        fi
    done

    if [[ $wasm_missing -eq 0 && $wasm_ok -gt 0 ]]; then
        pass "WASM plugin present on all $wasm_ok APISIX pods"
    elif [[ $wasm_ok -gt 0 ]]; then
        warn "WASM plugin present on $wasm_ok/$total_pods pods ($wasm_missing missing)"
    else
        fail "WASM plugin not found on any APISIX pod"
    fi

    # Check waf-coraza PluginConfig exists
    subheader "WAF PluginConfig"
    local waf_pc
    waf_pc=$(kubectl get pluginconfig -n apisix waf-coraza -o json 2>/dev/null)
    if [[ -n "$waf_pc" ]]; then
        pass "PluginConfig 'waf-coraza' found"

        # Parse WAF configuration
        local directives
        directives=$(echo "$waf_pc" | jq -r '.spec.plugins[0].config.conf.directives_map.default[]?' 2>/dev/null)

        # Check SecRuleEngine status
        if echo "$directives" | grep -q "SecRuleEngine On"; then
            pass "SecRuleEngine: On (blocking mode)"
        elif echo "$directives" | grep -q "SecRuleEngine DetectionOnly"; then
            warn "SecRuleEngine: DetectionOnly (not blocking)"
        else
            warn "SecRuleEngine status unclear"
        fi

        # Check if CRS is included
        if echo "$directives" | grep -q "@owasp_crs"; then
            pass "OWASP Core Rule Set (CRS) v4 enabled"
        else
            warn "OWASP CRS not detected in configuration"
        fi
    else
        fail "PluginConfig 'waf-coraza' not found"
    fi

    # Check HTTPRoutes using WAF
    subheader "HTTPRoutes with WAF Protection"
    local routes_with_waf
    routes_with_waf=$(kubectl get httproutes -A -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.rules[]?.filters[]?.extensionRef.name == "waf-coraza") | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
    if [[ -n "$routes_with_waf" ]]; then
        local waf_route_count
        waf_route_count=$(echo "$routes_with_waf" | wc -l | tr -d ' ')
        pass "$waf_route_count HTTPRoutes using WAF protection"
    else
        warn "No HTTPRoutes using waf-coraza ExtensionRef filter"
    fi

    # Check WAF test CronJob
    subheader "WAF Test Automation"
    local waf_cronjob
    waf_cronjob=$(kubectl get cronjob -n apisix waf-test --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${waf_cronjob:-0} -gt 0 ]]; then
        local waf_last
        waf_last=$(kubectl get cronjob -n apisix waf-test -o jsonpath='{.status.lastScheduleTime}' 2>/dev/null || echo "")
        local waf_last_success
        waf_last_success=$(kubectl get cronjob -n apisix waf-test -o jsonpath='{.status.lastSuccessfulTime}' 2>/dev/null || echo "")
        local waf_time="${waf_last:-$waf_last_success}"
        if [[ -n "$waf_time" ]]; then
            if [[ -n "$waf_last_success" ]]; then
                pass "WAF test CronJob: last successful run at $waf_last_success"
            else
                warn "WAF test CronJob: scheduled at $waf_last but no successful run recorded"
            fi
        else
            warn "WAF test CronJob exists but never scheduled"
        fi
    else
        info "WAF test CronJob not deployed"
    fi
}

check_tls13() {
    header "🔒 TLS 1.3 ENFORCEMENT"

    # Test API server TLS version (using config variables)
    if [[ -n "$API_VIP" ]]; then
        subheader "API Server TLS"
        local tls_version
        tls_version=$(echo | timeout 5 openssl s_client -connect "${API_VIP}:${API_PORT}" 2>/dev/null | grep "Protocol" | awk '{print $3}')

        if [[ "$tls_version" == "TLSv1.3" ]]; then
            pass "API server using TLS 1.3"
        elif [[ -n "$tls_version" ]]; then
            warn "API server using $tls_version (expected TLS 1.3)"
        else
            info "Could not determine API server TLS version"
        fi

        # Verify TLS 1.2 is rejected
        local tls12_result
        tls12_result=$(echo | timeout 5 openssl s_client -connect "${API_VIP}:${API_PORT}" -tls1_2 2>&1 | grep -i "alert\|error" | head -1)
        if [[ "$tls12_result" == *"protocol"* || "$tls12_result" == *"handshake"* ]]; then
            pass "TLS 1.2 correctly rejected by API server"
        else
            warn "TLS 1.2 rejection check inconclusive"
        fi
    fi

    # Check Kanidm OIDC endpoint TLS
    if [[ -n "$KANIDM_IP" ]]; then
        subheader "Kanidm OIDC TLS"
        local kanidm_tls
        kanidm_tls=$(echo | timeout 5 openssl s_client -connect "${KANIDM_IP}:${KANIDM_PORT}" 2>/dev/null | grep "Protocol" | awk '{print $3}')
        if [[ "$kanidm_tls" == "TLSv1.3" ]]; then
            pass "Kanidm using TLS 1.3"
        elif [[ -n "$kanidm_tls" ]]; then
            info "Kanidm using $kanidm_tls"
        fi
    fi
}

check_pdbs() {
    header "🛡️  POD DISRUPTION BUDGETS"

    # Get all PDBs
    local pdbs
    pdbs=$(kubectl get pdb -A -o json 2>/dev/null)
    local total_pdbs
    total_pdbs=$(echo "$pdbs" | jq '.items | length')

    if [[ ${total_pdbs:-0} -eq 0 ]]; then
        warn "No PodDisruptionBudgets configured"
        return
    fi

    info "Total PDBs: $total_pdbs"

    # Check for PDBs blocking evictions
    local blocking_pdbs
    blocking_pdbs=$(echo "$pdbs" | jq -r '.items[] |
        select(.status.disruptionsAllowed == 0 and .status.currentHealthy < .status.desiredHealthy) |
        "\(.metadata.namespace)/\(.metadata.name): currentHealthy=\(.status.currentHealthy), desiredHealthy=\(.status.desiredHealthy)"')

    if [[ -n "$blocking_pdbs" ]]; then
        fail "PDBs blocking evictions:"
        echo "$blocking_pdbs" | while read line; do
            echo "    $line"
        done
    else
        pass "No PDBs blocking node drains"
    fi

    # Check critical PDBs exist
    subheader "Critical PDBs"
    local critical_pdbs=("kyverno:kyverno-admission-controller" "kube-system:coredns" "kube-system:cilium-operator")
    for pdb_spec in "${critical_pdbs[@]}"; do
        IFS=':' read -r ns name <<< "$pdb_spec"
        local pdb_exists
        pdb_exists=$(kubectl get pdb -n "$ns" "$name" --no-headers 2>/dev/null | wc -l | tr -d ' ')
        if [[ ${pdb_exists:-0} -gt 0 ]]; then
            pass "PDB exists: $ns/$name"
        else
            warn "Missing critical PDB: $ns/$name"
        fi
    done
}
