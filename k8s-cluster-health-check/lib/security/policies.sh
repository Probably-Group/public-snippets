#!/bin/bash
# Security policy health checks
# Kyverno, Trivy, Supply Chain Security, Policy Reporter

# Source helpers (only if not already loaded)
if [[ -z "${HEALTH_CHECK_HELPERS_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    source "$SCRIPT_DIR/helpers.sh"
    source "$SCRIPT_DIR/pod-checks.sh"
fi

check_kyverno() {
    header "🛡️  KYVERNO POLICY ENGINE"

    # Check Kyverno pods
    local kyverno_ready
    kyverno_ready=$(kubectl get pods -n kyverno --no-headers 2>/dev/null | grep -c "Running" || true)

    if [[ $kyverno_ready -ge 8 ]]; then
        pass "Kyverno pods: $kyverno_ready running"
    else
        warn "Kyverno pods: $kyverno_ready running (expected 8+)"
    fi

    # Check version
    local kyverno_version
    kyverno_version=$(helper_get_pod_version "kyverno" "app.kubernetes.io/component=admission-controller")
    info "Kyverno version: $kyverno_version"

    # Check policies
    subheader "Policy Status"
    local policies
    policies=$(kubectl get clusterpolicies -o json 2>/dev/null)
    local total_policies
    total_policies=$(echo "$policies" | jq '.items | length')
    local ready_policies
    ready_policies=$(echo "$policies" | jq '[.items[] | select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))] | length')

    if [[ $ready_policies -eq $total_policies && $total_policies -gt 0 ]]; then
        pass "All $total_policies policies ready"
    else
        fail "Policies: $ready_policies/$total_policies ready"
    fi

    # Check policy violations
    local violations
    violations=$(kubectl get policyreports -A -o json 2>/dev/null | jq '[.items[].results[]? | select(.result=="fail")] | length')
    if [[ ${violations:-0} -gt 0 ]]; then
        warn "Policy violations: $violations"
    else
        pass "No policy violations"
    fi
}

check_trivy() {
    header "🔍 TRIVY VULNERABILITY SCANNER"

    helper_check_pods_ready "trivy-system" "app.kubernetes.io/name=trivy-operator" "Trivy operator"

    # Check vulnerability reports
    local vuln_reports
    vuln_reports=$(kubectl get vulnerabilityreports -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    info "Vulnerability reports: $vuln_reports"

    # Check for critical vulnerabilities
    local critical_vulns
    critical_vulns=$(kubectl get vulnerabilityreports -A -o json 2>/dev/null | jq '[.items[].report.summary.criticalCount // 0] | add')
    local high_vulns
    high_vulns=$(kubectl get vulnerabilityreports -A -o json 2>/dev/null | jq '[.items[].report.summary.highCount // 0] | add')

    if [[ ${critical_vulns:-0} -gt 0 ]]; then
        warn "Critical vulnerabilities found: $critical_vulns"
    else
        pass "No critical vulnerabilities"
    fi

    if [[ ${high_vulns:-0} -gt 10 ]]; then
        warn "High vulnerabilities: $high_vulns"
    else
        info "High vulnerabilities: ${high_vulns:-0}"
    fi
}

check_supply_chain_security() {
    header "🔐 SUPPLY CHAIN SECURITY (IMAGE SIGNING)"

    # Check cosign signing key
    subheader "Signing Infrastructure"
    local signing_key_es
    signing_key_es=$(kubectl get externalsecret cosign-signing-key -n argo-workflows -o json 2>/dev/null)
    if [[ -n "$signing_key_es" ]]; then
        local es_status
        es_status=$(echo "$signing_key_es" | jq -r '.status.conditions[]? | select(.type=="Ready") | .status')
        if [[ "$es_status" == "True" ]]; then
            pass "Cosign signing key ExternalSecret synced"
        else
            fail "Cosign signing key ExternalSecret not ready"
        fi
    else
        warn "Cosign signing key ExternalSecret not found in argo-workflows"
    fi

    # Check cosign secret has required keys
    local signing_secret
    signing_secret=$(kubectl get secret cosign-signing-key -n argo-workflows -o jsonpath='{.data}' 2>/dev/null)
    if [[ -n "$signing_secret" ]]; then
        local has_key
        has_key=$(echo "$signing_secret" | jq -r 'has("cosign.key")')
        local has_password
        has_password=$(echo "$signing_secret" | jq -r 'has("cosign.password")')
        if [[ "$has_key" == "true" && "$has_password" == "true" ]]; then
            pass "Cosign secret has required keys (cosign.key, cosign.password)"
        else
            fail "Cosign secret missing required keys"
        fi
    else
        warn "Cosign signing secret not found"
    fi

    # Check Kyverno supply chain policies
    subheader "Kyverno Image Verification Policies"
    local verify_policy
    verify_policy=$(kubectl get clusterpolicy verify-internal-image-signatures -o json 2>/dev/null)
    if [[ -n "$verify_policy" ]]; then
        local policy_action
        policy_action=$(echo "$verify_policy" | jq -r '.spec.validationFailureAction // "unknown"')

        if [[ "$policy_action" == "Enforce" ]]; then
            pass "Image signature verification: ENFORCING"
        elif [[ "$policy_action" == "Audit" ]]; then
            info "Image signature verification: Audit mode (not blocking)"
        else
            warn "Image signature verification: $policy_action"
        fi
    else
        warn "Image signature verification policy not deployed"
    fi

    # Check digest mutation policy
    local digest_policy
    digest_policy=$(kubectl get clusterpolicy mutate-image-digest -o json 2>/dev/null)
    if [[ -n "$digest_policy" ]]; then
        local digest_action
        digest_action=$(echo "$digest_policy" | jq -r '.spec.validationFailureAction // "unknown"')
        if [[ "$digest_action" == "Enforce" ]]; then
            pass "Image digest mutation: ENFORCING"
        else
            info "Image digest mutation: $digest_action"
        fi
    else
        warn "Image digest mutation policy not deployed"
    fi

    # Check build-sign-image WorkflowTemplate
    subheader "CI/CD Pipeline"
    local workflow_template
    workflow_template=$(kubectl get workflowtemplate build-sign-image -n argo-workflows --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ ${workflow_template:-0} -gt 0 ]]; then
        pass "build-sign-image WorkflowTemplate available"
    else
        warn "build-sign-image WorkflowTemplate not found"
    fi
}

check_policy_reporter() {
    header "📋 POLICY REPORTER (KYVERNO REPORTING)"

    # Check Policy Reporter pods
    local pr_ready
    pr_ready=$(kubectl get pods -n policy-reporter --no-headers 2>/dev/null | grep -c "Running" || true)
    local pr_total
    pr_total=$(kubectl get pods -n policy-reporter --no-headers 2>/dev/null | grep -v "Completed\|Error" | wc -l | tr -d ' ')

    if [[ $pr_ready -eq $pr_total && $pr_total -gt 0 ]]; then
        pass "Policy Reporter pods: $pr_ready/$pr_total running"
    elif [[ ${pr_total:-0} -eq 0 ]]; then
        info "Policy Reporter not deployed"
        return
    else
        fail "Policy Reporter pods: $pr_ready/$pr_total running"
    fi

    # Count policy violations by severity
    subheader "Policy Violations Summary"
    local reports
    reports=$(kubectl get policyreports -A -o json 2>/dev/null)
    if [[ -n "$reports" ]]; then
        local fail_count
        fail_count=$(echo "$reports" | jq '[.items[].results[]? | select(.result=="fail")] | length')
        local warn_count
        warn_count=$(echo "$reports" | jq '[.items[].results[]? | select(.result=="warn")] | length')
        local pass_count
        pass_count=$(echo "$reports" | jq '[.items[].results[]? | select(.result=="pass")] | length')

        if [[ ${fail_count:-0} -gt 0 ]]; then
            warn "Policy violations (FAIL): $fail_count"
        else
            pass "No policy failures"
        fi

        info "Policy warnings: ${warn_count:-0}"
        info "Policy passes: ${pass_count:-0}"
    fi

    helper_check_service "policy-reporter" "policy-reporter-ui" "Policy Reporter UI"
}

check_tetragon() {
    header "👁️  TETRAGON RUNTIME SECURITY"

    helper_check_pods_ready "kube-system" "app.kubernetes.io/name=tetragon" "Tetragon agents"

    # Check operator
    local operator_ready
    operator_ready=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon-operator --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ $operator_ready -gt 0 ]]; then
        pass "Tetragon operator running"
    else
        fail "Tetragon operator not running"
    fi
}

check_policy_controller() {
    header "📝 SIGSTORE POLICY CONTROLLER"

    # Check Policy Controller webhook
    local webhook_ready
    webhook_ready=$(kubectl get pods -n cosign-system -l app.kubernetes.io/name=policy-controller --no-headers 2>/dev/null | grep -c "Running" || true)
    if [[ ${webhook_ready:-0} -gt 0 ]]; then
        pass "Policy Controller webhook running"
    else
        fail "Policy Controller webhook not running"
    fi

    # Check webhook configuration
    local webhook_config
    webhook_config=$(kubectl get validatingwebhookconfigurations policy.sigstore.dev -o name 2>/dev/null || echo "")
    if [[ -n "$webhook_config" ]]; then
        pass "Validating webhook configured"
    else
        warn "Validating webhook not configured"
    fi
}
