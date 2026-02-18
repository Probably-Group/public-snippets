#!/bin/bash
# =============================================================================
# Kubernetes Cluster Health Check - Configuration
# =============================================================================
#
# Copy this file to config.sh and customize for your cluster:
#   cp config.example.sh config.sh
#
# All values below have sensible defaults. Override only what differs
# in your environment.
# =============================================================================

# -----------------------------------------------------------------------------
# Cluster Access
# -----------------------------------------------------------------------------

# Path to your kubeconfig file
# KUBECONFIG="/path/to/your/kubeconfig"

# Space-separated list of node IPs (used for talosctl commands)
# NODES="192.168.1.101 192.168.1.102 192.168.1.103"

# Cluster display name (shown in health check header)
# CLUSTER_NAME="my-cluster"

# -----------------------------------------------------------------------------
# Network Topology
# -----------------------------------------------------------------------------

# Kubernetes API server VIP (Virtual IP)
# API_VIP="192.168.1.100"

# Kubernetes API server port
# API_PORT="6443"

# Network gateway IP (used to validate Talos DNS nameserver config)
# GATEWAY_IP="192.168.1.1"

# CoreDNS external service IP (used to detect circular DNS dependency)
# COREDNS_EXTERNAL_IP="192.168.1.122"

# -----------------------------------------------------------------------------
# OIDC / Identity Provider
# -----------------------------------------------------------------------------

# Kanidm (or other OIDC provider) IP address
# KANIDM_IP="192.168.1.118"

# Kanidm HTTPS port
# KANIDM_PORT="443"

# OIDC discovery endpoint path (appended to https://<KANIDM_IP>)
# OIDC_PATH="/oauth2/openid/kubernetes/.well-known/openid-configuration"

# -----------------------------------------------------------------------------
# Node Naming
# -----------------------------------------------------------------------------

# Space-separated list of node hostname suffixes
# Used to construct API server pod names: kube-apiserver-<CLUSTER_NAME>-<hostname>
# NODE_HOSTNAMES="node01 node02 node03"

# Node IP used for etcd cluster status check (typically the first node)
# ETCD_CHECK_NODE="192.168.1.101"

# -----------------------------------------------------------------------------
# DNS Validation
# -----------------------------------------------------------------------------

# Acceptable external DNS servers in Talos nameserver config
# Space-separated list of IPs that are valid "first nameserver" entries
# VALID_EXTERNAL_DNS="8.8.8.8 1.1.1.1 192.168.1.1"
