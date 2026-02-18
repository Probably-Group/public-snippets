#!/bin/bash
# Cluster infrastructure health checks
# Nodes, Talos, etcd, Cilium, APISIX, CoreDNS

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_nodes() {
    header "🖥️  NODE HEALTH"

    local ready_nodes
    ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c "Ready" || true)
    local total_nodes
    total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [[ $ready_nodes -eq $total_nodes && $total_nodes -gt 0 ]]; then
        pass "All $total_nodes nodes Ready"
    else
        fail "Only $ready_nodes/$total_nodes nodes Ready"
    fi

    # Check node conditions
    for condition in MemoryPressure DiskPressure PIDPressure; do
        local issues
        issues=$(kubectl get nodes -o jsonpath="{.items[*].status.conditions[?(@.type=='$condition')].status}" 2>/dev/null | grep -c "True" || true)
        if [[ ${issues:-0} -gt 0 ]]; then
            fail "$issues node(s) have $condition"
        else
            pass "No $condition on any node"
        fi
    done

    # Check resource usage
    if kubectl top nodes &>/dev/null; then
        subheader "Resource Usage"
        kubectl top nodes 2>/dev/null | while read line; do
            if [[ "$line" != *"NAME"* ]]; then
                local cpu_pct
                cpu_pct=$(echo "$line" | awk '{print $3}' | tr -d '%')
                local mem_pct
                mem_pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
                local node_name
                node_name=$(echo "$line" | awk '{print $1}')

                if [[ ${cpu_pct:-0} -gt 90 ]]; then
                    warn "$node_name: CPU at ${cpu_pct}%"
                elif [[ ${mem_pct:-0} -gt 90 ]]; then
                    warn "$node_name: Memory at ${mem_pct}%"
                else
                    info "$node_name: CPU ${cpu_pct}%, Memory ${mem_pct}%"
                fi
            fi
        done
    fi
}

check_talos() {
    header "🐧 TALOS LINUX HEALTH"

    for node in $NODES; do
        subheader "Node $node"

        # Check Talos API
        if talosctl -n $node version &>/dev/null; then
            local version
            version=$(talosctl -n $node version --short 2>/dev/null | grep "Tag:" | head -1 | awk '{print $2}')
            pass "Talos API reachable (${version:-unknown})"
        else
            fail "Cannot reach Talos API"
            continue
        fi

        # Check services
        local etcd_status
        etcd_status=$(talosctl -n $node service etcd 2>/dev/null | grep "STATE" | awk '{print $2}')
        if [[ "$etcd_status" == "Running" ]]; then
            pass "etcd running"
        else
            fail "etcd not running (state: $etcd_status)"
        fi

        local kubelet_status
        kubelet_status=$(talosctl -n $node service kubelet 2>/dev/null | grep "STATE" | awk '{print $2}')
        if [[ "$kubelet_status" == "Running" ]]; then
            pass "kubelet running"
        else
            fail "kubelet not running (state: $kubelet_status)"
        fi

        # Check OOM kills
        local oom_count
        oom_count=$(talosctl -n $node dmesg 2>/dev/null | grep -ci "oom\|out of memory" || true)
        if [[ ${oom_count:-0} -gt 0 ]]; then
            warn "OOM events detected: $oom_count"
        else
            pass "No OOM events"
        fi
    done
}

check_etcd_health() {
    header "🗃️  ETCD CLUSTER HEALTH"

    for node in $NODES; do
        subheader "Node $node"

        # Check etcd member health via Talos
        local member_health
        member_health=$(talosctl -n $node etcd members 2>/dev/null | grep -v "NODE\|---" | head -3)
        if [[ -n "$member_health" ]]; then
            local learner_count
            learner_count=$(echo "$member_health" | grep -c "true" || true)
            if [[ ${learner_count:-0} -eq 0 ]]; then
                pass "etcd member healthy (not learner)"
            else
                warn "etcd member is learner"
            fi
        else
            warn "Could not get etcd member info from $node"
        fi

        # Check etcd alarms
        local alarms
        alarms=$(talosctl -n $node etcd alarm list 2>/dev/null | grep -v "^$" | wc -l | tr -d ' ')
        if [[ ${alarms:-0} -le 1 ]]; then
            pass "No etcd alarms"
        else
            fail "etcd alarms detected: $((alarms - 1))"
        fi
    done

    # Check etcd status via API (using configured check node)
    subheader "Cluster Status"
    local etcd_check
    etcd_check="${ETCD_CHECK_NODE:-$(echo $NODES | awk '{print $1}')}"
    local etcd_status
    etcd_status=$(talosctl -n "$etcd_check" etcd status 2>/dev/null)
    if [[ -n "$etcd_status" ]]; then
        local leader_id
        leader_id=$(echo "$etcd_status" | awk 'NR==2 {print $5}')
        local members_agree
        members_agree=$(echo "$etcd_status" | awk 'NR>1 {print $5}' | sort -u | wc -l | tr -d ' ')

        if [[ -n "$leader_id" && "$leader_id" != "LEADER" ]]; then
            if [[ ${members_agree:-0} -eq 1 ]]; then
                pass "etcd cluster has 1 leader (ID: ${leader_id:0:8}...)"
            else
                warn "etcd members disagree on leader ($members_agree different leaders)"
            fi
        else
            fail "etcd cluster has no leader"
        fi
    fi

    # Check database size
    for node in $NODES; do
        local db_size
        db_size=$(talosctl -n $node etcd status 2>/dev/null | awk 'NR==2 {print $3}' | tr -d 'MB')
        if [[ -n "$db_size" && "$db_size" =~ ^[0-9]+$ ]]; then
            if [[ $db_size -gt 6000 ]]; then
                fail "etcd DB size on $node: ${db_size}MB (>6GB - defrag needed)"
            elif [[ $db_size -gt 4000 ]]; then
                warn "etcd DB size on $node: ${db_size}MB (>4GB)"
            else
                info "etcd DB size on $node: ${db_size}MB"
            fi
        fi
    done
}

check_cilium() {
    header "🌐 CILIUM NETWORK HEALTH"

    # Check Cilium pods
    helper_check_pods_ready "kube-system" "k8s-app=cilium" "Cilium agents"

    # Check Cilium operator
    local operator_ready
    operator_ready=$(kubectl get pods -n kube-system -l name=cilium-operator --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $operator_ready -gt 0 ]]; then
        pass "Cilium operator running"
    else
        fail "Cilium operator not running"
    fi

    # Check Hubble
    local hubble_relay
    hubble_relay=$(kubectl get pods -n kube-system -l k8s-app=hubble-relay --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $hubble_relay -gt 0 ]]; then
        pass "Hubble Relay running"
    else
        warn "Hubble Relay not running"
    fi

    # Check WireGuard encryption (mTLS)
    subheader "WireGuard Encryption (mTLS)"
    local wg_enabled
    wg_enabled=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.enable-wireguard}' 2>/dev/null)
    if [[ "$wg_enabled" == "true" ]]; then
        pass "WireGuard encryption enabled in config"

        # Check each node's encryption status
        local nodes_with_wg=0
        local total_cilium_pods=0

        for pod in $(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
            ((total_cilium_pods++))
            local encrypt_status
            encrypt_status=$(kubectl exec -n kube-system $pod -c cilium-agent -- cilium-dbg encrypt status 2>/dev/null || echo "error")

            if [[ "$encrypt_status" == *"Wireguard"* ]]; then
                ((nodes_with_wg++))
            fi
        done

        if [[ $nodes_with_wg -eq $total_cilium_pods && $total_cilium_pods -gt 0 ]]; then
            pass "WireGuard active on all $total_cilium_pods nodes"
        else
            fail "WireGuard only on $nodes_with_wg/$total_cilium_pods nodes"
        fi

        # Verify mesh connectivity
        local expected_peers
        expected_peers=$((total_cilium_pods - 1))
        local mesh_ok=true
        for pod in $(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
            local peer_count
            peer_count=$(kubectl exec -n kube-system $pod -c cilium-agent -- cilium-dbg encrypt status 2>/dev/null | grep "Number of peers" | awk '{print $4}')
            if [[ "$peer_count" != "$expected_peers" ]]; then
                mesh_ok=false
            fi
        done

        if [[ "$mesh_ok" == "true" ]]; then
            pass "Full mesh: each node has $expected_peers peer(s)"
        else
            warn "Incomplete mesh: some nodes missing peers"
        fi
    else
        fail "WireGuard encryption NOT enabled"
    fi

    # Check network policy validity
    subheader "Network Policy Validity"
    local invalid_ccnp
    invalid_ccnp=$(kubectl get ccnp -o json 2>/dev/null | jq -r '.items[] | select(.status.conditions[0].status != "True") | .metadata.name' 2>/dev/null)
    local total_ccnp
    total_ccnp=$(kubectl get ccnp --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [[ -z "$invalid_ccnp" ]]; then
        pass "All $total_ccnp CiliumClusterwideNetworkPolicies valid"
    else
        for policy in $invalid_ccnp; do
            fail "CCNP '$policy' invalid"
        done
    fi

    local total_cnp
    total_cnp=$(kubectl get cnp -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    pass "CiliumNetworkPolicies: $total_cnp configured"

    # Check Cilium L2 repair CronJob
    subheader "L2 Repair Automation"
    local l2_cronjob
    l2_cronjob=$(kubectl get cronjob -n kube-system cilium-l2-repair --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${l2_cronjob:-0} -gt 0 ]]; then
        local l2_last_schedule
        l2_last_schedule=$(kubectl get cronjob -n kube-system cilium-l2-repair -o jsonpath='{.status.lastScheduleTime}' 2>/dev/null || echo "")
        if [[ -n "$l2_last_schedule" ]]; then
            pass "Cilium L2 repair CronJob active (last: $l2_last_schedule)"
        else
            warn "Cilium L2 repair CronJob exists but never scheduled"
        fi
    else
        warn "Cilium L2 repair CronJob not deployed"
    fi
}

check_apisix() {
    header "🚦 APISIX INGRESS HEALTH"

    # Get APISIX data plane pods
    local apisix_pods
    apisix_pods=$(kubectl get pods -n apisix -l app.kubernetes.io/name=apisix --no-headers 2>/dev/null)
    local apisix_ready
    apisix_ready=$(echo "$apisix_pods" | grep -c " 1/1 " 2>/dev/null || echo "0")
    local apisix_total
    apisix_total=$(echo "$apisix_pods" | wc -l | tr -d ' ')

    if [[ $apisix_ready -eq $apisix_total && $apisix_total -gt 0 ]]; then
        pass "APISIX data plane: $apisix_ready/$apisix_total ready"
    else
        warn "APISIX data plane: $apisix_ready/$apisix_total ready"
    fi

    # Get IC pods
    helper_check_pods_containers "apisix" "app.kubernetes.io/name=apisix-ingress-controller" "2/2" "APISIX Ingress Controller"

    # Check Gateway status
    local gateway_ready
    gateway_ready=$(kubectl get gateway -n apisix apisix-gateway -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || echo "Unknown")
    if [[ "$gateway_ready" == "True" ]]; then
        pass "Gateway 'apisix-gateway' accepted"
    else
        warn "Gateway status: $gateway_ready"
    fi

    # Check HTTPRoutes
    local httproute_count
    httproute_count=$(kubectl get httproutes -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    info "HTTPRoutes configured: $httproute_count"
}

check_coredns() {
    header "📡 DNS HEALTH"

    local dns_ready
    dns_ready=$(kubectl get pods -n kube-system -l k8s-app=kube-dns --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $dns_ready -ge 2 ]]; then
        pass "CoreDNS replicas: $dns_ready running"
    else
        fail "CoreDNS replicas: only $dns_ready running"
    fi

    helper_check_service "kube-system" "kube-dns" "DNS"
}
