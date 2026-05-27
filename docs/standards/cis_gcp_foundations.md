# CIS Google Cloud Platform Foundations Benchmark

- **Version:** 3.0.0
- **URL:** <https://www.cisecurity.org/benchmark/google_cloud_computing_platform>
- **Source of truth:** `pipeline_check/core/standards/data/cis_gcp_foundations.py`

CIS Google Cloud Platform Foundations Benchmark, CI/CD-relevant subset.
Covers IAM, Cloud Storage, Cloud KMS, and Cloud Logging controls.

## At a glance

- **Controls in this standard:** 12
- **Controls evidenced by at least one check:** 12 / 12
- **Distinct checks evidencing this standard:** 15
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.4`](#ctrl-1-4) | Ensure that Service Account has no Admin privileges | 1 | 1C |
| [`1.5`](#ctrl-1-5) | Ensure that Service Account Keys are managed and rotated | 1 | 1H |
| [`1.6`](#ctrl-1-6) | Ensure IAM Users are not assigned SA User or Token Creator roles at project level | 1 | 1H |
| [`2.1`](#ctrl-2-1) | Ensure Cloud Audit Logging is configured properly for all services and all users in a project | 1 | 1H |
| [`2.2`](#ctrl-2-2) | Ensure that sinks are configured for all log entries | 1 | 1M |
| [`2.3`](#ctrl-2-3) | Ensure log metric filter and alerts exist for Audit Configuration changes | 1 | 1M |
| [`2.12`](#ctrl-2-12) | Ensure that Cloud Audit Logging is configured properly | 1 | 1H |
| [`5.1`](#ctrl-5-1) | Ensure that Cloud Storage bucket is not anonymously or publicly accessible | 5 | 3H · 2M |
| [`5.2`](#ctrl-5-2) | Ensure that Cloud Storage buckets have uniform bucket-level access enabled | 1 | 1M |
| [`7.1`](#ctrl-7-1) | Ensure KMS Encryption Keys are rotated within a period of 365 days | 1 | 1M |
| [`7.2`](#ctrl-7-2) | Ensure KMS Encryption Keys are not anonymously or publicly accessible | 1 | 1H |
| [`7.3`](#ctrl-7-3) | Ensure KMS keys are protected by a Hardware Security Module (HSM) | 1 | 1L |

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

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-001`](../providers/gcp.md) | Service account has Owner or Editor role on project | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GCP](../providers/gcp.md) |  |

### 1.5: Ensure that Service Account Keys are managed and rotated { #ctrl-1-5 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-002`](../providers/gcp.md) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 1.6: Ensure IAM Users are not assigned SA User or Token Creator roles at project level { #ctrl-1-6 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCIAM-003`](../providers/gcp.md) | Service account token creator granted without constraint | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 2.1: Ensure Cloud Audit Logging is configured properly for all services and all users in a project { #ctrl-2-1 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-001`](../providers/gcp.md) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 2.2: Ensure that sinks are configured for all log entries { #ctrl-2-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-002`](../providers/gcp.md) | No log sink configured for audit logs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 2.3: Ensure log metric filter and alerts exist for Audit Configuration changes { #ctrl-2-3 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-003`](../providers/gcp.md) | Log bucket retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 2.12: Ensure that Cloud Audit Logging is configured properly { #ctrl-2-12 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCLOG-001`](../providers/gcp.md) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 5.1: Ensure that Cloud Storage bucket is not anonymously or publicly accessible { #ctrl-5-1 }

**Evidenced by 5 checks** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GAR-001`](../providers/gcp.md) | Artifact Registry repository has no vulnerability scanning | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GAR-002`](../providers/gcp.md) | Artifact Registry repository is publicly readable | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GAR-003`](../providers/gcp.md) | Artifact Registry has no cleanup policy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-001`](../providers/gcp.md) | Cloud Storage bucket is publicly accessible | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-003`](../providers/gcp.md) | Bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 5.2: Ensure that Cloud Storage buckets have uniform bucket-level access enabled { #ctrl-5-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCS-002`](../providers/gcp.md) | Bucket does not enforce uniform bucket-level access | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 7.1: Ensure KMS Encryption Keys are rotated within a period of 365 days { #ctrl-7-1 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-001`](../providers/gcp.md) | KMS key rotation period exceeds 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |

### 7.2: Ensure KMS Encryption Keys are not anonymously or publicly accessible { #ctrl-7-2 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-002`](../providers/gcp.md) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |

### 7.3: Ensure KMS keys are protected by a Hardware Security Module (HSM) { #ctrl-7-3 }

**Evidenced by 1 check** across GCP.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCKMS-003`](../providers/gcp.md) | KMS key not using HSM protection level | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_gcp_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_gcp_foundations`._
