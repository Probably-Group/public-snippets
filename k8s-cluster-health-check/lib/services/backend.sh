#!/bin/bash
# Backend services health checks
# RabbitMQ, dn-api, Celery workers, KEDA

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

# ============================================================================
# RABBITMQ OPERATOR (rabbitmq-system namespace)
# ============================================================================

check_rabbitmq_operator() {
    header "🐰 RABBITMQ OPERATOR"

    # Check Cluster Operator
    subheader "Cluster Operator"
    local cluster_op
    cluster_op=$(kubectl get pods -n rabbitmq-system -l app.kubernetes.io/name=rabbitmq-cluster-operator --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${cluster_op:-0} -gt 0 ]]; then
        pass "RabbitMQ Cluster Operator running"
    else
        fail "RabbitMQ Cluster Operator not running"
    fi

    # Check Messaging Topology Operator
    subheader "Messaging Topology Operator"
    local topology_op
    topology_op=$(kubectl get pods -n rabbitmq-system -l app.kubernetes.io/name=messaging-topology-operator --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${topology_op:-0} -gt 0 ]]; then
        pass "Messaging Topology Operator running"
    else
        warn "Messaging Topology Operator not running"
    fi

    # Check CRDs are installed
    subheader "Custom Resource Definitions"
    local cluster_crd
    cluster_crd=$(kubectl get crd rabbitmqclusters.rabbitmq.com --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local binding_crd
    binding_crd=$(kubectl get crd bindings.rabbitmq.com --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${cluster_crd:-0} -gt 0 ]]; then
        pass "RabbitmqCluster CRD installed"
    else
        fail "RabbitmqCluster CRD not installed"
    fi

    if [[ ${binding_crd:-0} -gt 0 ]]; then
        pass "Messaging Topology CRDs installed"
    else
        warn "Messaging Topology CRDs not installed"
    fi

    # Check operator image source (should be Chainguard)
    subheader "Image Source (Security)"
    local operator_image
    operator_image=$(kubectl get pods -n rabbitmq-system -l app.kubernetes.io/name=rabbitmq-cluster-operator -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null || echo "unknown")
    if [[ "$operator_image" == *"cgr.dev/chainguard"* ]]; then
        pass "Using Chainguard image (0 CVEs)"
    elif [[ "$operator_image" == *"bitnami"* ]]; then
        warn "Using Bitnami image (high CVE risk)"
    else
        info "Image: $operator_image"
    fi
}

# ============================================================================
# RABBITMQ CLUSTER (rabbitmq namespace)
# ============================================================================

check_rabbitmq_cluster() {
    header "🐇 RABBITMQ CLUSTER"

    # Check if RabbitmqCluster exists
    local cluster_count
    cluster_count=$(kubectl get rabbitmqcluster -n rabbitmq --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${cluster_count:-0} -eq 0 ]]; then
        info "No RabbitMQ cluster deployed"
        return 0
    fi

    # Get cluster status
    local cluster_name
    cluster_name=$(kubectl get rabbitmqcluster -n rabbitmq -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    local cluster_ready
    cluster_ready=$(kubectl get rabbitmqcluster -n rabbitmq "$cluster_name" -o jsonpath='{.status.conditions[?(@.type=="AllReplicasReady")].status}' 2>/dev/null || echo "Unknown")

    subheader "Cluster Status: $cluster_name"
    if [[ "$cluster_ready" == "True" ]]; then
        pass "RabbitMQ cluster all replicas ready"
    else
        warn "RabbitMQ cluster not fully ready (AllReplicasReady: $cluster_ready)"
    fi

    # Check pods
    local rabbitmq_pods
    rabbitmq_pods=$(kubectl get pods -n rabbitmq -l app.kubernetes.io/component=rabbitmq --no-headers 2>/dev/null)
    local rabbitmq_running
    rabbitmq_running=$(echo "$rabbitmq_pods" | grep -c "Running" 2>/dev/null || echo "0")

    helper_check_quorum "$rabbitmq_running" 3 "RabbitMQ pods"

    # Check cluster partition status
    subheader "Cluster Health"
    local rabbitmq_pod
    rabbitmq_pod=$(kubectl get pods -n rabbitmq -l app.kubernetes.io/component=rabbitmq -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$rabbitmq_pod" ]]; then
        # Check for network partitions via cluster_status (list_partitions command doesn't exist in newer RabbitMQ)
        local partition_status
        partition_status=$(kubectl exec -n rabbitmq "$rabbitmq_pod" -- rabbitmqctl cluster_status 2>/dev/null | grep -A2 "Network Partitions" | grep -v "Network Partitions" | tr -d '[:space:]')
        if [[ "$partition_status" == "(none)" || -z "$partition_status" ]]; then
            pass "No network partitions detected"
        else
            fail "Network partition detected in RabbitMQ cluster: $partition_status"
        fi

        # Check queue count
        local queue_count
        queue_count=$(kubectl exec -n rabbitmq "$rabbitmq_pod" -- rabbitmqctl list_queues 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
        info "Queues configured: $queue_count"
    fi

    # Check service
    helper_check_service "rabbitmq" "$cluster_name" "RabbitMQ"

    # Check for quorum queue default
    subheader "Configuration"
    local default_queue_type
    default_queue_type=$(kubectl get rabbitmqcluster -n rabbitmq "$cluster_name" -o jsonpath='{.spec.rabbitmq.additionalConfig}' 2>/dev/null | grep -o "default_queue_type = quorum" || echo "")
    if [[ -n "$default_queue_type" ]]; then
        pass "Default queue type: quorum (HA)"
    else
        warn "Default queue type not set to quorum"
    fi
}

# ============================================================================
# DN-API BACKEND (dn-api namespace)
# ============================================================================

check_dn_api() {
    header "⚡ DN-API BACKEND"

    # Check if namespace exists
    local ns_exists
    ns_exists=$(kubectl get namespace dn-api --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${ns_exists:-0} -eq 0 ]]; then
        info "dn-api namespace not deployed"
        return 0
    fi

    # Check API pods
    subheader "FastAPI Application"
    local api_pods
    api_pods=$(kubectl get pods -n dn-api -l app.kubernetes.io/name=dn-api --no-headers 2>/dev/null)
    local api_running
    api_running=$(echo "$api_pods" | grep "Running" 2>/dev/null | wc -l | tr -d ' ')
    local api_pullbackoff
    api_pullbackoff=$(echo "$api_pods" | grep -E "ImagePullBackOff|ErrImagePull" 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${api_pullbackoff:-0} -gt 0 ]]; then
        fail "dn-api pods in ImagePullBackOff - image not built?"
    elif [[ ${api_running:-0} -gt 0 ]]; then
        pass "dn-api pods running: $api_running"
    else
        fail "dn-api pods not running"
    fi

    # Check Celery workers
    subheader "Celery Workers"
    local celery_pods
    celery_pods=$(kubectl get pods -n dn-api -l app.kubernetes.io/name=dn-api-celery-worker --no-headers 2>/dev/null)
    local celery_running
    celery_running=$(echo "$celery_pods" | grep "Running" 2>/dev/null | wc -l | tr -d ' ')
    local celery_pullbackoff
    celery_pullbackoff=$(echo "$celery_pods" | grep -E "ImagePullBackOff|ErrImagePull" 2>/dev/null | wc -l | tr -d ' ')

    # Check if KEDA ScaledObject manages Celery workers (scale-to-zero is normal)
    local keda_managed
    keda_managed=$(kubectl get scaledobject -n dn-api dn-api-celery-worker --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${celery_pullbackoff:-0} -gt 0 ]]; then
        fail "Celery workers in ImagePullBackOff"
    elif [[ ${celery_running:-0} -gt 0 ]]; then
        pass "Celery workers running: $celery_running"
    elif [[ ${keda_managed:-0} -gt 0 ]]; then
        pass "Celery workers scaled to zero (KEDA - no tasks queued)"
    else
        warn "Celery workers not running"
    fi

    # Check ExternalSecret sync
    subheader "Secrets Sync"
    local ext_secret_status
    ext_secret_status=$(kubectl get externalsecret -n dn-api dn-api-secrets -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
    if [[ "$ext_secret_status" == "True" ]]; then
        pass "ExternalSecret synced from OpenBao"
    elif [[ "$ext_secret_status" == "Unknown" ]]; then
        info "ExternalSecret not configured"
    else
        warn "ExternalSecret not synced (Ready: $ext_secret_status)"
    fi

    # Check service
    helper_check_service "dn-api" "dn-api" "dn-api"

    # Check recent errors in logs (if pods are running)
    if [[ ${api_running:-0} -gt 0 ]]; then
        subheader "Recent Errors"
        local api_errors
        api_errors=$(kubectl logs -n dn-api -l app.kubernetes.io/name=dn-api --tail=100 2>/dev/null | \
            grep -ci "error\|exception\|traceback" || true)
        if [[ ${api_errors:-0} -gt 10 ]]; then
            warn "High error count in API logs: $api_errors"
        else
            pass "Low error count in API logs: $api_errors"
        fi
    fi

    # Check RabbitMQ connectivity
    subheader "RabbitMQ Connectivity"
    if [[ ${celery_running:-0} -gt 0 ]]; then
        local broker_errors
        broker_errors=$(kubectl logs -n dn-api -l app.kubernetes.io/name=dn-api-celery-worker --tail=50 2>/dev/null | \
            grep -ci "connection refused\|broker.*error\|amqp.*error" || true)
        if [[ ${broker_errors:-0} -gt 0 ]]; then
            warn "RabbitMQ connection errors: $broker_errors"
        else
            pass "Celery connected to RabbitMQ"
        fi
    fi
}

# ============================================================================
# MESSAGING TOPOLOGY (exchanges, queues, bindings)
# ============================================================================

check_messaging_topology() {
    header "📬 MESSAGING TOPOLOGY"

    # Check if topology resources exist
    local exchanges
    exchanges=$(kubectl get exchanges.rabbitmq.com -n rabbitmq --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local queues
    queues=$(kubectl get queues.rabbitmq.com -n rabbitmq --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local bindings
    bindings=$(kubectl get bindings.rabbitmq.com -n rabbitmq --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if [[ ${exchanges:-0} -eq 0 && ${queues:-0} -eq 0 && ${bindings:-0} -eq 0 ]]; then
        info "No messaging topology resources deployed"
        return 0
    fi

    # Check exchanges
    if [[ ${exchanges:-0} -gt 0 ]]; then
        local exchange_ready
        exchange_ready=$(kubectl get exchanges.rabbitmq.com -n rabbitmq -o json 2>/dev/null | \
            jq '[.items[] | select(.status.conditions[]?.type=="Ready" and .status.conditions[]?.status=="True")] | length')
        if [[ $exchange_ready -eq $exchanges ]]; then
            pass "Exchanges ready: $exchange_ready/$exchanges"
        else
            warn "Exchanges ready: $exchange_ready/$exchanges"
        fi
    fi

    # Check queues
    if [[ ${queues:-0} -gt 0 ]]; then
        local queue_ready
        queue_ready=$(kubectl get queues.rabbitmq.com -n rabbitmq -o json 2>/dev/null | \
            jq '[.items[] | select(.status.conditions[]?.type=="Ready" and .status.conditions[]?.status=="True")] | length')
        if [[ $queue_ready -eq $queues ]]; then
            pass "Queues ready: $queue_ready/$queues"
        else
            warn "Queues ready: $queue_ready/$queues"
        fi
    fi

    # Check bindings
    if [[ ${bindings:-0} -gt 0 ]]; then
        local binding_ready
        binding_ready=$(kubectl get bindings.rabbitmq.com -n rabbitmq -o json 2>/dev/null | \
            jq '[.items[] | select(.status.conditions[]?.type=="Ready" and .status.conditions[]?.status=="True")] | length')
        if [[ $binding_ready -eq $bindings ]]; then
            pass "Bindings ready: $binding_ready/$bindings"
        else
            warn "Bindings ready: $binding_ready/$bindings"
        fi
    fi
}

# ============================================================================
# KEDA EVENT-DRIVEN AUTOSCALING
# ============================================================================

check_keda() {
    header "⚡ KEDA AUTOSCALING"

    # Check KEDA operator
    subheader "KEDA Operator"
    local keda_operator
    keda_operator=$(kubectl get pods -n keda -l app=keda-operator --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${keda_operator:-0} -gt 0 ]]; then
        pass "KEDA operator running"
    else
        fail "KEDA operator not running"
    fi

    # Check KEDA metrics apiserver
    local keda_metrics
    keda_metrics=$(kubectl get pods -n keda -l app=keda-operator-metrics-apiserver --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${keda_metrics:-0} -gt 0 ]]; then
        pass "KEDA metrics apiserver running"
    else
        fail "KEDA metrics apiserver not running"
    fi

    # Check KEDA admission webhooks
    local keda_webhooks
    keda_webhooks=$(kubectl get pods -n keda -l app=keda-admission-webhooks --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${keda_webhooks:-0} -gt 0 ]]; then
        pass "KEDA admission webhooks running"
    else
        warn "KEDA admission webhooks not running"
    fi

    # Check ScaledObjects across cluster
    subheader "ScaledObjects"
    local scaled_objects
    scaled_objects=$(kubectl get scaledobject -A -o json 2>/dev/null)
    local total_so
    total_so=$(echo "$scaled_objects" | jq '.items | length' 2>/dev/null || echo "0")
    local ready_so
    ready_so=$(echo "$scaled_objects" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length' 2>/dev/null || echo "0")

    if [[ ${total_so:-0} -eq 0 ]]; then
        info "No ScaledObjects configured"
    elif [[ $ready_so -eq $total_so ]]; then
        pass "All $total_so ScaledObjects ready"
    else
        warn "ScaledObjects: $ready_so/$total_so ready"
        # List non-ready ScaledObjects
        local not_ready
        not_ready=$(echo "$scaled_objects" | jq -r '.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status!="True")) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
        if [[ -n "$not_ready" ]]; then
            echo "$not_ready" | while read line; do
                echo "    Not ready: $line"
            done
        fi
    fi

    # Check for scaler errors in KEDA operator logs
    subheader "Scaler Health"
    local scaler_errors
    scaler_errors=$(kubectl logs -n keda -l app=keda-operator --tail=50 2>/dev/null | \
        grep -ci "scaler error\|failed to get metrics" || true)
    if [[ ${scaler_errors:-0} -gt 5 ]]; then
        warn "Scaler errors in KEDA logs: $scaler_errors"
    else
        pass "No significant scaler errors"
    fi
}
