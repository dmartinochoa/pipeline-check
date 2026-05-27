# CIS Google Cloud Platform Foundations Benchmark

- **Version:** 3.0.0
- **URL:** <https://www.cisecurity.org/benchmark/google_cloud_computing_platform>
- **Source of truth:** `pipeline_check/core/standards/data/cis_gcp_foundations.py`

CIS Google Cloud Platform Foundations Benchmark, CI/CD-relevant subset.
Covers IAM, Cloud Storage, Cloud KMS, and Cloud Logging controls.

## At a glance

- **Controls in this standard:** 30
- **Controls evidenced by at least one check:** 29 / 30
- **Distinct checks evidencing this standard:** 50
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.4`](#ctrl-1-4) | Ensure that Service Account has no Admin privileges | 3 | 1C · 1H · 1M |
| [`1.5`](#ctrl-1-5) | Ensure that Service Account Keys are managed and rotated | 2 | 2H |
| [`1.6`](#ctrl-1-6) | Ensure IAM Users are not assigned SA User or Token Creator roles at project level | 1 | 1H |
| [`2.1`](#ctrl-2-1) | Ensure Cloud Audit Logging is configured properly for all services and all users in a project | 2 | 1H · 1M |
| [`2.2`](#ctrl-2-2) | Ensure that sinks are configured for all log entries | 1 | 1M |
| [`2.3`](#ctrl-2-3) | Ensure log metric filter and alerts exist for Audit Configuration changes | 6 | 6M |
| [`2.12`](#ctrl-2-12) | Ensure that Cloud Audit Logging is configured properly | 2 | 1H · 1M |
| [`5.1`](#ctrl-5-1) | Ensure that Cloud Storage bucket is not anonymously or publicly accessible | 7 | 3H · 4M |
| [`5.2`](#ctrl-5-2) | Ensure that Cloud Storage buckets have uniform bucket-level access enabled | 1 | 1M |
| [`7.1`](#ctrl-7-1) | Ensure KMS Encryption Keys are rotated within a period of 365 days | 2 | 2M |
| [`7.2`](#ctrl-7-2) | Ensure KMS Encryption Keys are not anonymously or publicly accessible | 2 | 2H |
| [`7.3`](#ctrl-7-3) | Ensure KMS keys are protected by a Hardware Security Module (HSM) | 2 | 2L |
| [`3.1`](#ctrl-3-1) | Ensure the default network does not exist in a project | 1 | 1M |
| [`3.6`](#ctrl-3-6) | Ensure that SSH access is restricted from the Internet | 1 | 1C |
| [`3.7`](#ctrl-3-7) | Ensure that RDP access is restricted from the Internet | 1 | 1C |
| [`3.8`](#ctrl-3-8) | Ensure that VPC flow logs are enabled for every subnet in a VPC network | 4 | 3M · 1L |
| [`3.9`](#ctrl-3-9) | Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites | 1 | 1M |
| [`3.10`](#ctrl-3-10) | Ensure firewall rules logging is enabled | 1 | 1M |
| [`4.1`](#ctrl-4-1) | Ensure that instances are not configured to use default service accounts | 3 | 2H · 1L |
| [`4.2`](#ctrl-4-2) | Ensure instances are not configured to use default SA with full Cloud API access | 1 | 1H |
| [`4.3`](#ctrl-4-3) | Ensure 'Block Project-wide SSH keys' is enabled for VM instances | 1 | 1M |
| [`4.4`](#ctrl-4-4) | Ensure oslogin is enabled for a project | 1 | 1M |
| [`4.5`](#ctrl-4-5) | Ensure 'Enable connecting to serial ports' is not enabled for a VM instance | 1 | 1M |
| [`4.6`](#ctrl-4-6) | Ensure that IP forwarding is not enabled on instances | 1 | 1H |
| [`4.11`](#ctrl-4-11) | Ensure Compute instances are launched with Shielded VM enabled | 1 | 1M |
| [`6.1`](#ctrl-6-1) | Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges | 2 | 1H · 1M |
| [`6.2`](#ctrl-6-2) | Ensure 'skip_show_database' database flag for Cloud SQL MySQL instance is set to 'on' | 0 | — |
| [`6.5`](#ctrl-6-5) | Ensure that Cloud SQL database instances are not open to the world | 1 | 1H |
| [`6.6`](#ctrl-6-6) | Ensure that Cloud SQL database instances do not have public IPs | 1 | 1H |
| [`6.7`](#ctrl-6-7) | Ensure that Cloud SQL database instances are configured with automated backups | 2 | 2M |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_gcp_foundations`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_gcp_foundations

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_gcp_foundations

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_gcp_foundations --standard owasp_cicd_top_10
```

## Controls in scope

### 1.4: Ensure that Service Account has no Admin privileges { #ctrl-1-4 }

**Evidenced by 3 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-001`](../providers/gcp.md) | Service account has Owner or Editor role on project | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GCP](../providers/gcp.md) |  |
| [`GCIAM-005`](../providers/gcp.md) | Domain-restricted sharing constraint not enforced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCRUN-001`](../providers/gcp.md) | Cloud Run service allows unauthenticated access | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 1.5: Ensure that Service Account Keys are managed and rotated { #ctrl-1-5 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-002`](../providers/gcp.md) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCIAM-006`](../providers/gcp.md) | Service account key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 1.6: Ensure IAM Users are not assigned SA User or Token Creator roles at project level { #ctrl-1-6 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-003`](../providers/gcp.md) | Service account token creator granted without constraint | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 2.1: Ensure Cloud Audit Logging is configured properly for all services and all users in a project { #ctrl-2-1 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-001`](../providers/gcp.md) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-006`](../providers/gcp.md) | Critical service missing Data Access audit log types | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 2.2: Ensure that sinks are configured for all log entries { #ctrl-2-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-002`](../providers/gcp.md) | No log sink configured for audit logs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 2.3: Ensure log metric filter and alerts exist for Audit Configuration changes { #ctrl-2-3 }

**Evidenced by 6 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-003`](../providers/gcp.md) | Log bucket retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-007`](../providers/gcp.md) | No log metric filter for IAM policy changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-008`](../providers/gcp.md) | No log metric filter for firewall rule changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-009`](../providers/gcp.md) | No log metric filter for route changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-010`](../providers/gcp.md) | No log metric filter for Cloud SQL config changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-011`](../providers/gcp.md) | No log metric filter for custom role changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 2.12: Ensure that Cloud Audit Logging is configured properly { #ctrl-2-12 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-001`](../providers/gcp.md) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-006`](../providers/gcp.md) | Critical service missing Data Access audit log types | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 5.1: Ensure that Cloud Storage bucket is not anonymously or publicly accessible { #ctrl-5-1 }

**Evidenced by 7 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GAR-001`](../providers/gcp.md) | Artifact Registry repository has no vulnerability scanning | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GAR-002`](../providers/gcp.md) | Artifact Registry repository is publicly readable | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GAR-003`](../providers/gcp.md) | Artifact Registry has no cleanup policy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-001`](../providers/gcp.md) | Cloud Storage bucket is publicly accessible | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-003`](../providers/gcp.md) | Bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-004`](../providers/gcp.md) | Cloud Storage bucket not encrypted with CMEK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-005`](../providers/gcp.md) | Cloud Storage bucket access logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 5.2: Ensure that Cloud Storage buckets have uniform bucket-level access enabled { #ctrl-5-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCS-002`](../providers/gcp.md) | Bucket does not enforce uniform bucket-level access | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 7.1: Ensure KMS Encryption Keys are rotated within a period of 365 days { #ctrl-7-1 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-001`](../providers/gcp.md) | KMS key rotation period exceeds 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-005`](../providers/gcp.md) | KMS key has primary version scheduled for destruction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 7.2: Ensure KMS Encryption Keys are not anonymously or publicly accessible { #ctrl-7-2 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-002`](../providers/gcp.md) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-004`](../providers/gcp.md) | KMS key ring IAM has overly broad bindings | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 7.3: Ensure KMS keys are protected by a Hardware Security Module (HSM) { #ctrl-7-3 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-003`](../providers/gcp.md) | KMS key not using HSM protection level | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-006`](../providers/gcp.md) | KMS key uses imported (external) key material | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |

### 3.1: Ensure the default network does not exist in a project { #ctrl-3-1 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCNET-001`](../providers/gcp.md) | Default VPC network exists in project | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 3.6: Ensure that SSH access is restricted from the Internet { #ctrl-3-6 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCNET-003`](../providers/gcp.md) | Firewall allows SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GCP](../providers/gcp.md) |  |

### 3.7: Ensure that RDP access is restricted from the Internet { #ctrl-3-7 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCNET-003`](../providers/gcp.md) | Firewall allows SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GCP](../providers/gcp.md) |  |

### 3.8: Ensure that VPC flow logs are enabled for every subnet in a VPC network { #ctrl-3-8 }

**Evidenced by 4 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-004`](../providers/gcp.md) | VPC Flow Logs not enabled on subnet | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCNET-004`](../providers/gcp.md) | Subnet does not have Private Google Access enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCNET-005`](../providers/gcp.md) | No Cloud NAT gateway configured | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |
| [`GCRUN-004`](../providers/gcp.md) | Cloud Run service does not use a VPC connector | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 3.9: Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites { #ctrl-3-9 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCNET-002`](../providers/gcp.md) | No default-deny ingress firewall rule configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 3.10: Ensure firewall rules logging is enabled { #ctrl-3-10 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-005`](../providers/gcp.md) | Firewall rule logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 4.1: Ensure that instances are not configured to use default service accounts { #ctrl-4-1 }

**Evidenced by 3 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-004`](../providers/gcp.md) | Compute instance uses default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCRUN-002`](../providers/gcp.md) | Cloud Run service or function uses default compute SA | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCRUN-003`](../providers/gcp.md) | Cloud Run service has zero minimum instances | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |

### 4.2: Ensure instances are not configured to use default SA with full Cloud API access { #ctrl-4-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-004`](../providers/gcp.md) | Compute instance uses default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 4.3: Ensure 'Block Project-wide SSH keys' is enabled for VM instances { #ctrl-4-3 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCCE-005`](../providers/gcp.md) | Instance does not block project-wide SSH keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 4.4: Ensure oslogin is enabled for a project { #ctrl-4-4 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCCE-002`](../providers/gcp.md) | Compute instance does not have OS Login enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 4.5: Ensure 'Enable connecting to serial ports' is not enabled for a VM instance { #ctrl-4-5 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCCE-003`](../providers/gcp.md) | Compute instance has serial port access enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 4.6: Ensure that IP forwarding is not enabled on instances { #ctrl-4-6 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCCE-004`](../providers/gcp.md) | Compute instance has an external IP address | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 4.11: Ensure Compute instances are launched with Shielded VM enabled { #ctrl-4-11 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCCE-001`](../providers/gcp.md) | Compute instance does not have Shielded VM enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 6.1: Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges { #ctrl-6-1 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCSQL-003`](../providers/gcp.md) | Cloud SQL instance does not require SSL connections | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCSQL-004`](../providers/gcp.md) | Cloud SQL instance does not have IAM authentication enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 6.2: Ensure 'skip_show_database' database flag for Cloud SQL MySQL instance is set to 'on' { #ctrl-6-2 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 6.5: Ensure that Cloud SQL database instances are not open to the world { #ctrl-6-5 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCSQL-001`](../providers/gcp.md) | Cloud SQL instance has a public IP address | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 6.6: Ensure that Cloud SQL database instances do not have public IPs { #ctrl-6-6 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCSQL-001`](../providers/gcp.md) | Cloud SQL instance has a public IP address | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 6.7: Ensure that Cloud SQL database instances are configured with automated backups { #ctrl-6-7 }

**Evidenced by 2 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCSQL-002`](../providers/gcp.md) | Cloud SQL instance does not have automated backups enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCSQL-005`](../providers/gcp.md) | Cloud SQL instance does not have point-in-time recovery enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_gcp_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_gcp_foundations`._
