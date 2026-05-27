# CIS Microsoft Azure Foundations Benchmark

- **Version:** 2.1.0
- **URL:** <https://www.cisecurity.org/benchmark/azure>
- **Source of truth:** `pipeline_check/core/standards/data/cis_azure_foundations.py`

CIS Microsoft Azure Foundations Benchmark, CI/CD-relevant subset.
Covers identity (Entra ID), storage accounts, Key Vault, container
registry, and monitoring controls.

## At a glance

- **Controls in this standard:** 18
- **Controls evidenced by at least one check:** 16 / 18
- **Distinct checks evidencing this standard:** 15
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.21`](#ctrl-1-21) | Ensure that no custom subscription administrator roles are created | 1 | 1C |
| [`1.24`](#ctrl-1-24) | Ensure that custom role permissions are managed and reviewed | 1 | 1C |
| [`1.1.1`](#ctrl-1-1-1) | Ensure Security Defaults are enabled on Azure Active Directory | 1 | 1H |
| [`1.1.2`](#ctrl-1-1-2) | Ensure that multi-factor authentication is enabled for all privileged users | 1 | 1H |
| [`3.1`](#ctrl-3-1) | Ensure that 'Secure transfer required' is set to 'Enabled' | 1 | 1H |
| [`3.7`](#ctrl-3-7) | Ensure default network access rule for storage accounts is set to deny | 1 | 1H |
| [`3.10`](#ctrl-3-10) | Ensure storage account access keys are periodically regenerated | 0 | — |
| [`3.12`](#ctrl-3-12) | Ensure storage for critical data is encrypted with Customer-Managed Key | 1 | 1M |
| [`5.1.2`](#ctrl-5-1-2) | Ensure Diagnostic Setting captures appropriate categories | 2 | 1H · 1M |
| [`5.1.5`](#ctrl-5-1-5) | Ensure that logging for Azure Key Vault is 'Enabled' | 1 | 1M |
| [`5.2.1`](#ctrl-5-2-1) | Ensure that Activity Log Alert exists for Create Policy Assignment | 1 | 1M |
| [`5.2.2`](#ctrl-5-2-2) | Ensure that Activity Log Alert exists for Delete Policy Assignment | 1 | 1M |
| [`5.2.4`](#ctrl-5-2-4) | Ensure that Activity Log Alert exists for Create or Update Network Security Group | 1 | 1M |
| [`8.1`](#ctrl-8-1) | Ensure that the expiration date is set on all keys | 0 | — |
| [`8.4`](#ctrl-8-4) | Ensure the Key Vault is recoverable | 2 | 2H |
| [`8.5`](#ctrl-8-5) | Enable role-based access control for Azure Key Vault | 1 | 1M |
| [`9.1`](#ctrl-9-1) | Ensure Container Registry has admin user disabled | 2 | 2H |
| [`9.2`](#ctrl-9-2) | Ensure Container Registry has content trust enabled | 1 | 1M |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_azure_foundations`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_azure_foundations

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_azure_foundations

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_azure_foundations --standard owasp_cicd_top_10
```

## Controls in scope

### 1.21: Ensure that no custom subscription administrator roles are created { #ctrl-1-21 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-001`](../providers/azure_cloud.md) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 1.24: Ensure that custom role permissions are managed and reviewed { #ctrl-1-24 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-001`](../providers/azure_cloud.md) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 1.1.1: Ensure Security Defaults are enabled on Azure Active Directory { #ctrl-1-1-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-003`](../providers/azure_cloud.md) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 1.1.2: Ensure that multi-factor authentication is enabled for all privileged users { #ctrl-1-1-2 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-002`](../providers/azure_cloud.md) | App registration credential valid beyond 180 days | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.1: Ensure that 'Secure transfer required' is set to 'Enabled' { #ctrl-3-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-002`](../providers/azure_cloud.md) | Storage account allows non-HTTPS traffic | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.7: Ensure default network access rule for storage accounts is set to deny { #ctrl-3-7 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-001`](../providers/azure_cloud.md) | Storage account allows public blob access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.10: Ensure storage account access keys are periodically regenerated { #ctrl-3-10 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 3.12: Ensure storage for critical data is encrypted with Customer-Managed Key { #ctrl-3-12 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-003`](../providers/azure_cloud.md) | Storage account not encrypted with customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.1.2: Ensure Diagnostic Setting captures appropriate categories { #ctrl-5-1-2 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-001`](../providers/azure_cloud.md) | No diagnostic setting for subscription Activity Log | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-002`](../providers/azure_cloud.md) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.1.5: Ensure that logging for Azure Key Vault is 'Enabled' { #ctrl-5-1-5 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-002`](../providers/azure_cloud.md) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.2.1: Ensure that Activity Log Alert exists for Create Policy Assignment { #ctrl-5-2-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.2.2: Ensure that Activity Log Alert exists for Delete Policy Assignment { #ctrl-5-2-2 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.2.4: Ensure that Activity Log Alert exists for Create or Update Network Security Group { #ctrl-5-2-4 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 8.1: Ensure that the expiration date is set on all keys { #ctrl-8-1 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 8.4: Ensure the Key Vault is recoverable { #ctrl-8-4 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AKV-001`](../providers/azure_cloud.md) | Key Vault soft delete not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-002`](../providers/azure_cloud.md) | Key Vault purge protection not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 8.5: Enable role-based access control for Azure Key Vault { #ctrl-8-5 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AKV-003`](../providers/azure_cloud.md) | Key Vault allows access from all networks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.1: Ensure Container Registry has admin user disabled { #ctrl-9-1 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-001`](../providers/azure_cloud.md) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ACR-002`](../providers/azure_cloud.md) | Container registry allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.2: Ensure Container Registry has content trust enabled { #ctrl-9-2 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-003`](../providers/azure_cloud.md) | Container registry content trust not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_azure_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_azure_foundations`._
