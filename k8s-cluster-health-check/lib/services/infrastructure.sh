#!/bin/bash
# Infrastructure services health checks
# step-ca, ArgoCD, Velero, Zot, Argo Workflows

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_argocd() {
    header "🔄 ARGOCD HEALTH"

    # Check ArgoCD pods
    helper_check_pods_ready "argocd" "" "ArgoCD pods"

    # Check version
    local argocd_version
    argocd_version=$(helper_get_pod_version "argocd" "app.kubernetes.io/name=argocd-server")
    info "ArgoCD version: $argocd_version"

    # Check applications
    subheader "Application Status"

    local apps
    apps=$(kubectl get applications -n argocd -o json 2>/dev/null)
    local app_names
    app_names=$(echo "$apps" | jq -r '.items[].metadata.name')

    for app in $app_names; do
        local sync_status
        sync_status=$(echo "$apps" | jq -r ".items[] | select(.metadata.name==\"$app\") | .status.sync.status")
        local health_status
        health_status=$(echo "$apps" | jq -r ".items[] | select(.metadata.name==\"$app\") | .status.health.status")

        if [[ "$sync_status" == "Synced" && "$health_status" == "Healthy" ]]; then
            pass "$app: Synced/Healthy"
        elif [[ "$health_status" == "Progressing" ]]; then
            info "$app: $sync_status/$health_status"
        elif [[ "$sync_status" == "OutOfSync" ]]; then
            warn "$app: OutOfSync ($health_status)"
        elif [[ "$health_status" == "Degraded" || "$health_status" == "Missing" ]]; then
            fail "$app: $sync_status/$health_status"
        else
            warn "$app: $sync_status/$health_status"
        fi
    done
}

check_argocd_repos() {
    header "🔗 ARGOCD REPOSITORY CONNECTIVITY"

    # Get repository connection status
    local repos
    repos=$(kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=repository -o json 2>/dev/null)
    local repo_count
    repo_count=$(echo "$repos" | jq '.items | length')

    if [[ ${repo_count:-0} -eq 0 ]]; then
        info "No ArgoCD repositories configured via secrets"
    else
        info "Configured repositories: $repo_count"
    fi

    # Check ArgoCD application-controller can reach repos
    local controller_logs
    controller_logs=$(kubectl logs -n argocd deployment/argocd-application-controller --tail=50 2>/dev/null)
    local repo_errors
    repo_errors=$(echo "$controller_logs" | grep -ci "failed to load repo\|repository not found\|authentication required" || true)

    if [[ ${repo_errors:-0} -gt 0 ]]; then
        warn "Repository errors in ArgoCD logs: $repo_errors"
    else
        pass "No repository connection errors in recent logs"
    fi
}

check_velero() {
    header "💾 VELERO BACKUP HEALTH"

    # Check Velero pods
    local velero_ready
    velero_ready=$(kubectl get pods -n velero --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${velero_ready:-0} -gt 0 ]]; then
        pass "Velero pods running"
    else
        fail "Velero pods not running"
    fi

    # Check Backup Storage Location
    local bsl_status
    bsl_status=$(kubectl get backupstoragelocation -n velero -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Unknown")
    if [[ "$bsl_status" == "Available" ]]; then
        pass "Backup Storage Location: Available"
    else
        fail "Backup Storage Location: $bsl_status"
    fi

    # Check backup schedules
    subheader "Backup Schedules"
    local schedules
    schedules=$(kubectl get schedules.velero.io -n velero -o json 2>/dev/null)
    local total_schedules
    total_schedules=$(echo "$schedules" | jq '.items | length')
    local paused_schedules
    paused_schedules=$(echo "$schedules" | jq '[.items[] | select(.spec.paused == true)] | length')

    if [[ ${paused_schedules:-0} -gt 0 ]]; then
        warn "Paused backup schedules: $paused_schedules"
    else
        pass "All $total_schedules backup schedules active"
    fi

    # Check recent backups (last 48 hours)
    subheader "Recent Backups"
    local recent_backups
    recent_backups=$(kubectl get backups.velero.io -n velero -o json 2>/dev/null | \
        jq -r '[.items[] | select(.status.phase == "Completed") | select(.status.completionTimestamp) |
        select((.status.completionTimestamp | fromdateiso8601) > (now - 172800))] | length')

    if [[ ${recent_backups:-0} -gt 0 ]]; then
        pass "Successful backups in last 48h: $recent_backups"
    else
        fail "No successful backups in last 48 hours"
    fi

    # Check for failed backups
    local failed_backups
    failed_backups=$(kubectl get backups.velero.io -n velero -o json 2>/dev/null | \
        jq -r '[.items[] | select(.status.phase == "Failed" or .status.phase == "PartiallyFailed")] | length')
    if [[ ${failed_backups:-0} -gt 0 ]]; then
        warn "Failed/partial backups: $failed_backups"
    else
        pass "No failed backups"
    fi
}

check_step_ca() {
    header "🔐 STEP-CA INTERNAL PKI"

    # Check step-ca pod
    helper_check_pods_ready "step-ca" "" "step-ca pods"

    # Check step-issuer (runs in step-issuer namespace, not step-ca)
    subheader "Step Issuer"
    local issuer_ready
    issuer_ready=$(kubectl get pods -n step-issuer --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $issuer_ready -gt 0 ]]; then
        pass "step-issuer controller running"
    else
        fail "step-issuer controller not running"
    fi

    # Check StepClusterIssuer status
    local issuer_status
    issuer_status=$(kubectl get stepclusterissuers step-ca-issuer -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
    if [[ "$issuer_status" == "True" ]]; then
        pass "StepClusterIssuer ready"
    else
        fail "StepClusterIssuer not ready"
    fi

    # Check cert-manager
    subheader "Certificate Manager"
    helper_check_pods_ready "cert-manager" "" "cert-manager pods"

    # Check certificate count and expiration
    local cert_count
    cert_count=$(kubectl get certificates -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    local cert_ready
    cert_ready=$(kubectl get certificates -A -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]?.type=="Ready" and .status.conditions[]?.status=="True")] | length')

    if [[ ${cert_count:-0} -gt 0 ]]; then
        if [[ $cert_ready -eq $cert_count ]]; then
            pass "All $cert_count certificates ready"
        else
            warn "Certificates: $cert_ready/$cert_count ready"
        fi
    else
        info "No certificates configured"
    fi

    # Check for certificates expiring soon (< 48h)
    subheader "Certificate Expiration"
    local expiring_soon
    expiring_soon=$(kubectl get certificates -A -o json 2>/dev/null | jq -r '.items[] | select(.status.notAfter) | {name: .metadata.name, ns: .metadata.namespace, notAfter: .status.notAfter} | select((.notAfter | fromdateiso8601) < (now + 172800)) | "\(.ns)/\(.name): expires \(.notAfter)"' 2>/dev/null)
    if [[ -n "$expiring_soon" ]]; then
        warn "Certificates expiring within 48h:"
        echo "$expiring_soon" | while read line; do
            echo "    $line"
        done
    else
        pass "No certificates expiring within 48h"
    fi
}

check_zot() {
    header "📦 ZOT CONTAINER REGISTRY"

    # Check Zot pods
    local zot_ready
    zot_ready=$(kubectl get pods -n zot --no-headers 2>/dev/null | grep -c "Running" || true)
    local zot_crash
    zot_crash=$(kubectl get pods -n zot --no-headers 2>/dev/null | grep -c "CrashLoopBackOff" || true)

    if [[ ${zot_ready:-0} -gt 0 ]]; then
        pass "Zot registry running"
    elif [[ ${zot_crash:-0} -gt 0 ]]; then
        fail "Zot in CrashLoopBackOff - check startup probe path"
    else
        fail "Zot registry not running"
    fi

    helper_check_service "zot" "zot" "Zot"
    helper_check_loadbalancer "zot" "zot" "Zot"
}

check_argo_workflows() {
    header "⚙️  ARGO WORKFLOWS & EVENTS"

    # Check Argo Workflows controller
    subheader "Argo Workflows"
    local wf_controller
    wf_controller=$(kubectl get pods -n argo-workflows -l app=workflow-controller --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${wf_controller:-0} -gt 0 ]]; then
        pass "Argo Workflows controller running"
    else
        fail "Argo Workflows controller not running"
    fi

    # Check Argo Server
    local argo_server
    argo_server=$(kubectl get pods -n argo-workflows -l app=argo-server --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${argo_server:-0} -gt 0 ]]; then
        pass "Argo Server running"
    else
        warn "Argo Server not running"
    fi

    # Check running/pending workflows
    local running_wf
    running_wf=$(kubectl get workflows -n argo-workflows --no-headers 2>/dev/null | grep -c "Running" || true)
    local failed_wf
    failed_wf=$(kubectl get workflows -n argo-workflows --no-headers 2>/dev/null | grep -c "Failed" || true)
    local pending_wf
    pending_wf=$(kubectl get workflows -n argo-workflows --no-headers 2>/dev/null | grep -c "Pending" || true)

    info "Workflows: Running=$running_wf, Pending=$pending_wf, Failed=$failed_wf"

    if [[ ${failed_wf:-0} -gt 5 ]]; then
        warn "Multiple failed workflows: $failed_wf"
    fi

    # Check Argo Events
    subheader "Argo Events"
    local events_controller
    events_controller=$(kubectl get pods -n argo-events -l app.kubernetes.io/name=argo-events-controller-manager --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${events_controller:-0} -gt 0 ]]; then
        pass "Argo Events controller running"
    else
        fail "Argo Events controller not running"
    fi

    # Check Eventbus (NATS JetStream StatefulSet)
    subheader "Eventbus (NATS JetStream)"
    local eventbus_ready
    eventbus_ready=$(kubectl get pods -n argo-events -l app.kubernetes.io/name=eventbus --no-headers 2>/dev/null | grep -c "Running" || true)
    local eventbus_total
    eventbus_total=$(kubectl get pods -n argo-events -l app.kubernetes.io/name=eventbus --no-headers 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ ${eventbus_total:-0} -eq 0 ]]; then
        info "Eventbus not deployed"
    else
        helper_check_quorum "$eventbus_ready" "$eventbus_total" "Eventbus pods"
    fi
}

check_cnpg() {
    header "🐘 CLOUDNATIVEPG OPERATOR"

    # Check controller-manager pod
    local cnpg_ready
    cnpg_ready=$(kubectl get pods -n cnpg-system -l app.kubernetes.io/name=cloudnative-pg --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${cnpg_ready:-0} -gt 0 ]]; then
        pass "CNPG controller-manager running"
    else
        fail "CNPG controller-manager not running"
    fi

    # Check CRD existence
    local cnpg_crd
    cnpg_crd=$(kubectl get crd clusters.postgresql.cnpg.io --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${cnpg_crd:-0} -gt 0 ]]; then
        pass "CNPG Cluster CRD installed"
    else
        fail "CNPG Cluster CRD not installed"
    fi
}

check_dashboard_hub() {
    header "📊 DASHBOARD HUB"

    # Check pods
    local hub_ready
    hub_ready=$(kubectl get pods -n health-dashboard -l app.kubernetes.io/name=dashboard-hub --no-headers 2>/dev/null | grep -c "Running" || true)
    local hub_total
    hub_total=$(kubectl get pods -n health-dashboard -l app.kubernetes.io/name=dashboard-hub --no-headers 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ ${hub_ready:-0} -eq ${hub_total:-0} && ${hub_total:-0} -gt 0 ]]; then
        pass "Dashboard Hub pods: $hub_ready/$hub_total running"
    elif [[ ${hub_total:-0} -eq 0 ]]; then
        info "Dashboard Hub not deployed"
        return 0
    else
        fail "Dashboard Hub pods: $hub_ready/$hub_total running"
    fi

    # Check service
    helper_check_service "health-dashboard" "dashboard-hub" "Dashboard Hub"
}

check_argocd_image_updater() {
    header "🔄 ARGOCD IMAGE UPDATER"

    # Check Image Updater pod (runs in argocd namespace, not argocd-image-updater)
    local updater_ready
    updater_ready=$(kubectl get pods -n argocd -l app.kubernetes.io/name=argocd-image-updater --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${updater_ready:-0} -gt 0 ]]; then
        pass "ArgoCD Image Updater running"
    else
        fail "ArgoCD Image Updater not running"
    fi

    # Check for recent update errors
    local update_errors
    update_errors=$(kubectl logs -n argocd -l app.kubernetes.io/name=argocd-image-updater --tail=50 2>/dev/null | \
        grep -ci "error\|failed" || true)
    if [[ ${update_errors:-0} -gt 5 ]]; then
        warn "Image Updater errors in recent logs: $update_errors"
    else
        pass "No significant Image Updater errors"
    fi
}

check_image_presync() {
    header "📦 IMAGE PRE-SYNC"

    # Check image-presync CronJob
    local presync_cronjob
    presync_cronjob=$(kubectl get cronjob -n zot image-presync --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${presync_cronjob:-0} -gt 0 ]]; then
        local presync_last
        presync_last=$(kubectl get cronjob -n zot image-presync -o jsonpath='{.status.lastScheduleTime}' 2>/dev/null || echo "")
        if [[ -n "$presync_last" ]]; then
            pass "Image presync CronJob active (last: $presync_last)"
        else
            warn "Image presync CronJob exists but never scheduled"
        fi
    else
        info "Image presync CronJob not deployed"
    fi
}

check_dnscrypt_proxy() {
    header "🔐 DNSCRYPT-PROXY (PRIMARY DNS-OVER-HTTPS)"

    helper_check_pods_ready "kube-system" "app.kubernetes.io/name=dnscrypt-proxy" "dnscrypt-proxy pods"
    helper_check_service "kube-system" "dnscrypt-proxy" "dnscrypt-proxy"

    # Check for recent DNS resolution errors in logs
    local dns_errors
    dns_errors=$(kubectl logs -n kube-system -l app.kubernetes.io/name=dnscrypt-proxy --tail=50 2>/dev/null | \
        grep -ci "error\|timeout\|failed" || true)
    if [[ ${dns_errors:-0} -gt 5 ]]; then
        warn "DNS resolution errors in logs: $dns_errors"
    else
        pass "No significant DNS errors in recent logs"
    fi
}

check_smtp_relay() {
    header "📧 SMTP RELAY"

    # Check SMTP relay pods
    local smtp_ready
    smtp_ready=$(kubectl get pods -n smtp-relay --no-headers 2>/dev/null | grep -c "Running" || true)
    local smtp_total
    smtp_total=$(kubectl get pods -n smtp-relay --no-headers 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ $smtp_ready -eq $smtp_total && $smtp_total -gt 0 ]]; then
        pass "SMTP relay pods: $smtp_ready/$smtp_total running"
    elif [[ ${smtp_total:-0} -eq 0 ]]; then
        info "SMTP relay not deployed"
        return
    else
        fail "SMTP relay pods: $smtp_ready/$smtp_total running"
    fi

    helper_check_service "smtp-relay" "smtp-relay" "SMTP relay"
}
