#!/usr/bin/env bash
# Reusable pod checking helpers
# Eliminates 43+ duplicated pod readiness checks

# Source helpers if not already loaded
[[ -z "$NC" ]] && source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

# Check if pods matching a label are ready
# Usage: helper_check_pods_ready "namespace" "label-selector" "description"
# Note: If label is empty, all pods in namespace are checked
helper_check_pods_ready() {
    local ns="$1"
    local label="$2"
    local desc="$3"

    # Build kubectl args as array for safe argument building
    local -a kubectl_args=(-n "$ns" --no-headers)
    if [[ -n "$label" ]]; then
        kubectl_args+=(-l "$label")
    fi

    local ready
    ready=$(kubectl get pods "${kubectl_args[@]}" 2>/dev/null | grep -c "Running" || true)
    local total
    total=$(kubectl get pods "${kubectl_args[@]}" 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ ${ready:-0} -eq ${total:-0} && ${total:-0} -gt 0 ]]; then
        pass "$desc: $ready/$total running"
        return 0
    elif [[ ${ready:-0} -gt 0 ]]; then
        warn "$desc: $ready/$total running"
        return 1
    else
        fail "$desc: $ready/$total running"
        return 2
    fi
}

# Check quorum-based services (TiKV, Garage, etcd)
# Usage: helper_check_quorum "ready_count" "total_count" "description"
helper_check_quorum() {
    local ready="$1"
    local total="$2"
    local desc="$3"
    local quorum
    quorum=$((total / 2 + 1))

    if [[ ${ready:-0} -eq ${total:-0} && ${total:-0} -gt 0 ]]; then
        pass "$desc: $ready/$total running"
        return 0
    elif [[ ${ready:-0} -ge $quorum ]]; then
        warn "$desc: $ready/$total running (quorum maintained)"
        return 1
    else
        fail "$desc: $ready/$total running (QUORUM LOST!)"
        return 2
    fi
}

# Check pods with specific ready containers (e.g., "2/2")
# Usage: helper_check_pods_containers "namespace" "label-selector" "expected-ready" "description"
# Note: If label is empty, all pods in namespace are checked
helper_check_pods_containers() {
    local ns="$1"
    local label="$2"
    local expected_ready="$3"
    local desc="$4"

    # Build kubectl command - omit -l flag if label is empty
    local kubectl_cmd="kubectl get pods -n $ns --no-headers"
    if [[ -n "$label" ]]; then
        kubectl_cmd="$kubectl_cmd -l $label"
    fi

    local ready
    ready=$($kubectl_cmd 2>/dev/null | grep -c " ${expected_ready} " || echo "0")
    local total
    total=$($kubectl_cmd 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${ready:-0} -eq ${total:-0} && ${total:-0} -gt 0 ]]; then
        pass "$desc: $ready/$total ready"
        return 0
    else
        fail "$desc: $ready/$total ready"
        return 2
    fi
}

# Check for CrashLoopBackOff in a namespace
# Usage: helper_check_crashloop "namespace" "context_message"
helper_check_crashloop() {
    local ns="$1"
    local context="$2"

    local crash_pods
    crash_pods=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -c "CrashLoopBackOff" || true)
    if [[ ${crash_pods:-0} -gt 0 ]]; then
        fail "CrashLoopBackOff detected in $ns - $context"
        return 1
    fi
    return 0
}

# Check pod version from image tag
# Usage: helper_get_pod_version "namespace" "label-selector" "container-index"
# Note: If label is empty, first pod in namespace is used
helper_get_pod_version() {
    local ns="$1"
    local label="$2"
    local container_idx="${3:-0}"

    # Build kubectl command - omit -l flag if label is empty
    local kubectl_args="-n $ns"
    if [[ -n "$label" ]]; then
        kubectl_args="$kubectl_args -l $label"
    fi

    kubectl get pods $kubectl_args -o jsonpath="{.items[0].spec.containers[$container_idx].image}" 2>/dev/null | sed 's/.*://' | head -1 || echo "unknown"
}

# Check service exists and has endpoints
# Usage: helper_check_service "namespace" "service-name" "description"
helper_check_service() {
    local ns="$1"
    local svc_name="$2"
    local desc="$3"

    local svc_exists
    svc_exists=$(kubectl get svc -n "$ns" "$svc_name" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${svc_exists:-0} -gt 0 ]]; then
        pass "$desc service available"
        return 0
    else
        fail "$desc service not found"
        return 1
    fi
}

# Check LoadBalancer IP assignment
# Usage: helper_check_loadbalancer "namespace" "service-name" "description"
helper_check_loadbalancer() {
    local ns="$1"
    local svc_name="$2"
    local desc="$3"

    local lb_ip
    lb_ip=$(kubectl get svc -n "$ns" "$svc_name" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    if [[ -n "$lb_ip" ]]; then
        info "$desc LoadBalancer IP: $lb_ip"
        return 0
    else
        info "$desc using ClusterIP or no LoadBalancer assigned"
        return 1
    fi
}
