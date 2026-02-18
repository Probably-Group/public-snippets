# Kubernetes Cluster Health Check Script

A comprehensive, modular health check script for Kubernetes clusters running on Talos Linux with Cilium CNI. Covers 40+ checks across infrastructure, security, observability, and application services.

## Tech Stack Covered

- **OS:** Talos Linux (immutable, API-driven)
- **CNI:** Cilium (eBPF, WireGuard encryption, Hubble observability)
- **Storage:** Longhorn (distributed block), Garage S3 (object), Local PV/NVMe
- **Database:** SurrealDB + TiKV (distributed KV store)
- **GitOps:** ArgoCD + Kustomize
- **Ingress:** APISIX Gateway API + Coraza WAF
- **PKI:** step-ca + cert-manager
- **Secrets:** OpenBao + ExternalSecrets Operator
- **Identity:** Kanidm (OIDC), oauth2-proxy
- **Workload Identity:** SPIRE (mTLS service mesh via Cilium)
- **Policy:** Kyverno (PSS enforce), Tetragon (runtime security)
- **Observability:** VictoriaMetrics, Grafana, VictoriaLogs, Vector, Tempo, OTel Collector
- **Backup:** Velero (CSI snapshots to Garage S3)
- **CI/CD:** Argo Workflows + Argo Events
- **Messaging:** RabbitMQ (quorum queues)
- **Autoscaling:** KEDA (event-driven), HPA
- **Deception:** Honeypots, tarpits, scanner confuser

## Quick Start

### 1. Copy and configure

```bash
cp config.example.sh config.sh
# Edit config.sh with your cluster values
vim config.sh
```

### 2. Make executable

```bash
chmod +x health-check.sh
```

### 3. Run

```bash
# Full health check (all domains)
./health-check.sh

# Specific domain only
./health-check.sh cluster
./health-check.sh security
./health-check.sh observability
./health-check.sh services

# Specific check function
./health-check.sh check_nodes
./health-check.sh check_cilium
./health-check.sh check_velero
```

## Configuration

All cluster-specific values are externalized to `config.sh`. Copy `config.example.sh` and fill in your values:

| Variable | Description | Example |
|----------|-------------|---------|
| `KUBECONFIG` | Path to kubeconfig file | `$HOME/.kube/config` |
| `NODES` | Space-separated node IPs | `10.0.0.1 10.0.0.2 10.0.0.3` |
| `CLUSTER_NAME` | Cluster name (used in API server pod names) | `my-cluster` |
| `API_VIP` | Kubernetes API VIP | `10.0.0.100` |
| `API_PORT` | API server port | `6443` |
| `KANIDM_IP` | OIDC provider (Kanidm) IP | `10.0.0.118` |
| `KANIDM_PORT` | OIDC provider port | `443` |
| `COREDNS_EXTERNAL_IP` | CoreDNS external LB IP | `10.0.0.122` |
| `GATEWAY_IP` | Network gateway IP | `10.0.0.1` |
| `NODE_HOSTNAMES` | Node hostname suffixes | `node01 node02 node03` |
| `OIDC_PATH` | OIDC discovery path | `/oauth2/openid/kubernetes/.well-known/openid-configuration` |
| `ETCD_CHECK_NODE` | Node for etcd status checks | `10.0.0.1` |
| `VALID_EXTERNAL_DNS` | Valid external DNS servers | `8.8.8.8 8.8.4.4` |

Checks that depend on optional variables (e.g., `KANIDM_IP`, `API_VIP`) are skipped gracefully if the variable is empty.

## Directory Structure

```
health-check/
├── config.example.sh              # Configuration template (copy to config.sh)
├── config.sh                      # Your cluster config (gitignored)
├── health-check.sh                # Main entry point
├── README.md                      # This file
└── lib/
    ├── helpers.sh                 # Output formatting (pass/fail/warn/info)
    ├── pod-checks.sh              # Reusable pod readiness helpers
    ├── cluster/
    │   ├── infrastructure.sh      # Nodes, Talos, etcd, Cilium, APISIX, CoreDNS
    │   └── storage.sh             # Longhorn, SurrealDB/TiKV, Garage S3, NVMe
    ├── security/
    │   ├── authentication.sh      # OIDC, Kanidm, oauth2-proxy, SPIRE/mTLS
    │   ├── network.sh             # Cilium drops, WAF, TLS 1.3, PDBs
    │   ├── policies.sh            # Kyverno, Trivy, supply chain, Tetragon
    │   └── deception.sh           # Honeypots, tarpits, Valkey blocklist
    ├── observability/
    │   ├── monitoring.sh          # VictoriaMetrics, Grafana, alerts, Vector
    │   └── tracing.sh             # Tempo, OTel Collector
    └── services/
        ├── infrastructure.sh      # ArgoCD, Velero, step-ca, Zot, Argo Workflows
        └── backend.sh             # RabbitMQ, dn-api, Celery, KEDA
```

## What It Checks

### Cluster Infrastructure (12 checks)
- Node readiness, conditions (MemoryPressure, DiskPressure, PIDPressure)
- Talos API reachability, service health (etcd, kubelet), OOM detection
- etcd cluster health: member status, leader election, alarms, DB size
- Cilium agents, operator, Hubble relay, WireGuard mesh, network policy validity
- APISIX data plane, ingress controller, Gateway status, HTTPRoutes
- CoreDNS replicas and service

### Storage (4 checks)
- Longhorn managers, nodes, volumes, PVCs, encryption, over-provisioning
- SurrealDB pods, TiKV PD leader, store states, write stalls
- Garage S3 cluster connectivity, endpoint health
- Local PV/NVMe: disk usage per mount, NVMe errors, I/O errors

### Security (8 checks)
- OIDC: Kanidm pods, endpoint, API server config, CA cert, DNS config
- oauth2-proxy: pods, OIDC provider connectivity
- SPIRE: server, agents, CSI driver, registrations, Cilium integration, auth metrics
- External Secrets Operator: pods, CRD, sync status
- OpenBao: HA cluster, seal status, quorum, ClusterSecretStore, etcd encryption
- Cilium policy drops by reason and namespace
- WAF: WASM plugin, PluginConfig, HTTPRoutes, test CronJob
- TLS 1.3 enforcement on API server and Kanidm

### Observability (5 checks)
- VictoriaMetrics, VMAgent, Grafana, VMAlertmanager, VictoriaLogs, Vector
- Feature health alerts VMRule
- Active alert enumeration (critical/warning/info with color coding)
- Tempo distributed components, ingester WAL, OTel Collector, S3 backend
- Pod summary: running, pending, failed, high restart counts

### Services (10 checks)
- ArgoCD: pods, version, application sync/health status
- Velero: BSL, schedules, recent backups, failed backups
- step-ca: pods, StepClusterIssuer, cert-manager, certificate expiration
- Zot container registry, image pre-sync CronJob
- Argo Workflows & Events, Eventbus (NATS JetStream)
- RabbitMQ operator, cluster, partitions, queue config
- dn-api backend, Celery workers (KEDA scale-to-zero aware)
- Messaging topology (exchanges, queues, bindings)
- KEDA operator, metrics apiserver, ScaledObjects
- CloudNativePG, Dashboard Hub, Image Updater, dnscrypt-proxy, SMTP relay

## Scoring

The script outputs a health score out of 100 based on pass/warn/fail counts:

```
Score = max(0, 100 - (warnings × 1) - (failures × 3))
```

Exit codes:
- `0` — Score >= 80 (healthy)
- `1` — Score < 80 (needs attention)

## Adapting to Your Cluster

This script is designed for a specific tech stack but is modular enough to adapt:

1. **Remove checks you don't need** — Delete or comment out function calls in `health-check.sh`
2. **Add your own checks** — Create new `.sh` files in the appropriate `lib/` subdirectory
3. **Modify thresholds** — Each check has inline thresholds (e.g., restart counts, disk usage %)
4. **Change scoring** — Adjust the scoring formula in `health-check.sh`

### Minimum requirements

- `kubectl` configured and pointing at your cluster
- `talosctl` configured (for Talos-specific checks — skip if not using Talos)
- `jq` installed
- `openssl` installed (for TLS checks)

### Checks that require Talos

These checks use `talosctl` and can be removed if you don't run Talos Linux:

- `check_talos()` — Talos API, service health, OOM detection
- `check_local_pv_health()` — NVMe disk usage via `talosctl df`
- OIDC CA cert verification via `talosctl read`
- DNS nameserver verification via `talosctl get`

### Checks that are cluster-specific

These checks reference specific service names/namespaces and may need adjustment:

- `check_dn_api()` — References `dn-api` namespace and labels
- `check_deception()` — References deception infrastructure components
- `check_dashboard_hub()` — References `health-dashboard` namespace
- `check_dnscrypt_proxy()` — References dnscrypt-proxy in kube-system
- `check_smtp_relay()` — References smtp-relay namespace

## Dependencies

| Tool | Required | Used For |
|------|----------|----------|
| `kubectl` | Yes | All Kubernetes checks |
| `talosctl` | Optional | Talos-specific node checks |
| `jq` | Yes | JSON parsing |
| `openssl` | Optional | TLS version checks |
| `curl` | Optional | Metric queries (TiKV write stalls) |

## License

MIT — Use freely, adapt to your infrastructure.
