#!/bin/bash
# Storage health checks
# Longhorn, SurrealDB+TiKV, Garage S3, Local PV/NVMe

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_longhorn() {
    header "💾 LONGHORN STORAGE HEALTH"

    # Check Longhorn manager
    local manager_ready
    manager_ready=$(kubectl get pods -n longhorn-system -l app=longhorn-manager --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $manager_ready -ge 3 ]]; then
        pass "Longhorn managers: $manager_ready running"
    else
        warn "Longhorn managers: only $manager_ready running"
    fi

    # Check nodes
    local lh_nodes
    lh_nodes=$(kubectl get nodes.longhorn.io -n longhorn-system --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local lh_ready
    lh_ready=$(kubectl get nodes.longhorn.io -n longhorn-system -o json 2>/dev/null | jq '[.items[] | select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))] | length')

    if [[ $lh_ready -eq $lh_nodes && $lh_nodes -gt 0 ]]; then
        pass "Longhorn nodes: $lh_ready/$lh_nodes ready"
    else
        fail "Longhorn nodes: $lh_ready/$lh_nodes ready"
    fi

    # Check volumes
    subheader "Volume Status"
    local volumes
    volumes=$(kubectl get volumes.longhorn.io -n longhorn-system -o json 2>/dev/null)
    local total_vols
    total_vols=$(echo "$volumes" | jq '.items | length')
    local healthy_vols
    healthy_vols=$(echo "$volumes" | jq '[.items[] | select(.status.state=="attached" or .status.state=="detached")] | length')
    local degraded_vols
    degraded_vols=$(echo "$volumes" | jq '[.items[] | select(.status.robustness=="degraded")] | length')

    if [[ ${degraded_vols:-0} -gt 0 ]]; then
        warn "Degraded volumes: $degraded_vols"
    fi

    if [[ $healthy_vols -eq $total_vols && $total_vols -gt 0 ]]; then
        pass "All $total_vols volumes healthy"
    else
        warn "Volumes: $healthy_vols/$total_vols healthy"
    fi

    # Check PVCs
    local pvc_bound
    pvc_bound=$(kubectl get pvc -A --no-headers 2>/dev/null | grep -c "Bound" || true)
    local pvc_pending
    pvc_pending=$(kubectl get pvc -A --no-headers 2>/dev/null | grep -c "Pending" || true)

    if [[ ${pvc_pending:-0} -gt 0 ]]; then
        fail "PVCs pending: $pvc_pending"
    else
        pass "All PVCs bound ($pvc_bound total)"
    fi

    # Check Longhorn encryption
    subheader "Volume Encryption"
    local encrypted_sc
    encrypted_sc=$(kubectl get storageclass longhorn-encrypted -o jsonpath='{.metadata.name}' 2>/dev/null || echo "")
    if [[ "$encrypted_sc" == "longhorn-encrypted" ]]; then
        pass "StorageClass 'longhorn-encrypted' exists"
    else
        warn "StorageClass 'longhorn-encrypted' not found"
    fi

    # Check if longhorn-encrypted is the default StorageClass
    local default_sc
    default_sc=$(kubectl get storageclass -o json 2>/dev/null | jq -r '.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"]=="true") | .metadata.name')
    if [[ "$default_sc" == "longhorn-encrypted" ]]; then
        pass "Default StorageClass: longhorn-encrypted"
    elif [[ -n "$default_sc" ]]; then
        info "Default StorageClass: $default_sc (not encrypted)"
    else
        warn "No default StorageClass set"
    fi

    # Check longhorn-crypto secret exists
    local crypto_secret
    crypto_secret=$(kubectl get secret -n longhorn-system longhorn-crypto -o jsonpath='{.data.CRYPTO_KEY_VALUE}' 2>/dev/null || echo "")
    if [[ -n "$crypto_secret" ]]; then
        pass "Longhorn encryption key secret exists (longhorn-crypto)"
    else
        fail "Longhorn encryption key secret missing (longhorn-crypto)"
    fi

    # Check over-provisioning percentage (must be 200 for HA)
    local overprov
    overprov=$(kubectl get settings -n longhorn-system storage-over-provisioning-percentage -o jsonpath='{.value}' 2>/dev/null || echo "")
    if [[ "$overprov" == "200" ]]; then
        pass "Storage over-provisioning: 200% (correct for 2-node survival)"
    elif [[ -n "$overprov" ]]; then
        warn "Storage over-provisioning: ${overprov}% (should be 200 for HA)"
    else
        info "Could not check storage over-provisioning setting"
    fi
}

check_surrealdb() {
    header "🗄️  SURREALDB DATABASE"

    # Check SurrealDB pods
    helper_check_pods_ready "surrealdb" "app.kubernetes.io/name=surrealdb" "SurrealDB pods"
    helper_check_service "surrealdb" "surrealdb" "SurrealDB"
    helper_check_loadbalancer "surrealdb" "surrealdb" "SurrealDB"

    # ========== TiKV Cluster Health ==========
    subheader "TiKV Distributed Storage"

    # Check TiKV PD pods
    local pd_ready
    pd_ready=$(kubectl get pods -n surrealdb -l app.kubernetes.io/component=pd --no-headers 2>/dev/null | grep -c "Running" || true)
    helper_check_quorum "$pd_ready" 3 "TiKV PD cluster"

    # Check TiKV store pods
    local tikv_ready
    tikv_ready=$(kubectl get pods -n surrealdb -l app.kubernetes.io/component=tikv --no-headers 2>/dev/null | grep -c "Running" || true)
    helper_check_quorum "$tikv_ready" 3 "TiKV stores"

    # Check PD leader
    local pd_pod
    pd_pod=$(kubectl get pods -n surrealdb -l app.kubernetes.io/component=pd -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$pd_pod" ]]; then
        # Note: "member leader" alone shows help text, need "member leader show" for actual status
        local pd_leader
        pd_leader=$(kubectl exec -n surrealdb "$pd_pod" -- /pd-ctl member leader show 2>/dev/null | jq -r '.name // empty' 2>/dev/null || echo "")
        if [[ -n "$pd_leader" ]]; then
            pass "TiKV PD leader: $pd_leader"
        else
            fail "TiKV PD has no leader"
        fi

        # Check TiKV store states
        local store_up
        store_up=$(kubectl exec -n surrealdb "$pd_pod" -- /pd-ctl store 2>/dev/null | jq '[.stores[] | select(.store.state_name == "Up")] | length' 2>/dev/null || echo "0")
        helper_check_quorum "$store_up" 3 "TiKV stores Up"
    fi

    # Check for write stalls via metrics
    local write_stalls
    write_stalls=$(curl -sf "http://vmsingle-vm-stack-victoria-metrics-k8s-stack.monitoring.svc:8428/api/v1/query?query=sum(tikv_engine_write_stall)" 2>/dev/null | jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0")
    if [[ "$write_stalls" != "0" && -n "$write_stalls" && "$write_stalls" != "null" ]]; then
        fail "TiKV write stalls detected: $write_stalls events"
    else
        pass "TiKV no write stalls"
    fi
}

check_garage_cluster() {
    header "📦 GARAGE S3 STORAGE"

    # Check Garage pods
    local garage_ready
    garage_ready=$(kubectl get pods -n garage -l app.kubernetes.io/name=garage --no-headers 2>/dev/null | grep -c "Running" || true)
    helper_check_quorum "$garage_ready" 3 "Garage pods"

    # Check node connectivity via garage status
    # Note: Garage binary is at /garage and requires config file path
    local garage_pod
    garage_pod=$(kubectl get pods -n garage -l app.kubernetes.io/name=garage -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$garage_pod" ]]; then
        local garage_output
        garage_output=$(kubectl exec -n garage "$garage_pod" -- /garage -c /etc/garage/config/garage.toml status 2>/dev/null) || garage_output=""
        local connected_nodes
        if [[ -n "$garage_output" ]]; then
            # Garage status shows "HEALTHY NODES" section with node entries (ID, Hostname, Address, etc.)
            # Count lines that match node entry pattern (hex ID followed by hostname)
            connected_nodes=$(echo "$garage_output" | grep -E "^[0-9a-f]{16}\s+" | wc -l | tr -d ' ')
        else
            connected_nodes=0
        fi
        helper_check_quorum "$connected_nodes" 3 "Garage cluster nodes connected"

        # Check service endpoints exist (proves pods are serving)
        # Note: Garage image is minimal - no curl/wget, use service endpoint check instead
        local endpoints
        endpoints=$(kubectl get endpoints -n garage garage -o jsonpath='{.subsets[0].addresses}' 2>/dev/null | jq -r 'length' 2>/dev/null || echo "0")
        if [[ ${endpoints:-0} -ge 2 ]]; then
            pass "Garage S3 API healthy ($endpoints endpoints)"
        elif [[ ${endpoints:-0} -gt 0 ]]; then
            warn "Garage S3 API has only $endpoints endpoint(s)"
        else
            fail "Garage S3 API has no healthy endpoints"
        fi

        # Check web/admin service endpoints
        local admin_endpoints
        admin_endpoints=$(kubectl get endpoints -n garage garage-admin -o jsonpath='{.subsets[0].addresses}' 2>/dev/null | jq -r 'length' 2>/dev/null || echo "0")
        if [[ ${admin_endpoints:-0} -ge 2 ]]; then
            pass "Garage Admin API healthy ($admin_endpoints endpoints)"
        elif [[ ${admin_endpoints:-0} -gt 0 ]]; then
            warn "Garage Admin API has only $admin_endpoints endpoint(s)"
        else
            # Admin service may not exist - that's OK
            info "Garage Admin API service not configured (optional)"
        fi
    else
        fail "No Garage pods found to check cluster status"
    fi

    helper_check_service "garage" "garage" "Garage"
}

check_local_pv_health() {
    header "💾 LOCAL PV / NVME HEALTH"

    for node in $NODES; do
        subheader "Node $node"

        # Check NVMe disk space for important mount points
        local mounts_to_check="/var/lib/etcd /var/lib/containerd /var/lib/kubelet /var/lib/longhorn"

        for mount in $mounts_to_check; do
            local disk_info
            disk_info=$(talosctl -n "$node" df "$mount" 2>/dev/null | tail -1)
            if [[ -n "$disk_info" ]]; then
                local usage_pct
                usage_pct=$(echo "$disk_info" | awk '{print $5}' | tr -d '%')
                local avail
                avail=$(echo "$disk_info" | awk '{print $4}')

                if [[ ${usage_pct:-0} -gt 90 ]]; then
                    fail "$node $mount: ${usage_pct}% used (${avail} available) - CRITICAL"
                elif [[ ${usage_pct:-0} -gt 85 ]]; then
                    warn "$node $mount: ${usage_pct}% used (${avail} available)"
                else
                    pass "$node $mount: ${usage_pct}% used"
                fi
            fi
        done

        # Check for disk errors
        local nvme_errors
        nvme_errors=$(talosctl -n "$node" dmesg 2>/dev/null | grep -ci "nvme.*error\|blk_update_request.*error" || true)
        if [[ ${nvme_errors:-0} -gt 0 ]]; then
            warn "$node: $nvme_errors NVMe/disk errors in dmesg"
        else
            pass "$node: No NVMe/disk errors"
        fi

        # Check for I/O errors on real storage (nvme, mmcblk)
        # All sd* devices are Longhorn iSCSI volumes with transient errors during volume operations
        # sr* devices are phantom optical drives
        local io_errors
        io_errors=$(talosctl -n "$node" dmesg 2>/dev/null | grep -i "I/O error\|Buffer I/O error" | grep -E "nvme|mmcblk" | wc -l | tr -d ' ')
        if [[ ${io_errors:-0} -gt 0 ]]; then
            fail "$node: $io_errors I/O errors on primary storage (nvme/mmcblk)"
        else
            pass "$node: No I/O errors on primary storage"
        fi
    done
}
