# CIS Microsoft Azure Foundations Benchmark

- **Version:** 2.1.0
- **URL:** <https://www.cisecurity.org/benchmark/azure>
- **Source of truth:** `pipeline_check/core/standards/data/cis_azure_foundations.py`

CIS Microsoft Azure Foundations Benchmark, CI/CD-relevant subset.
Covers identity (Entra ID), storage accounts, Key Vault, container
registry, and monitoring controls.

## At a glance

- **Controls in this standard:** 35
- **Controls evidenced by at least one check:** 35 / 35
- **Distinct checks evidencing this standard:** 50
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.21`](#ctrl-1-21) | Ensure that no custom subscription administrator roles are created | 1 | 1C |
| [`1.24`](#ctrl-1-24) | Ensure that custom role permissions are managed and reviewed | 2 | 1C · 1M |
| [`1.1.1`](#ctrl-1-1-1) | Ensure Security Defaults are enabled on Azure Active Directory | 2 | 2H |
| [`1.1.2`](#ctrl-1-1-2) | Ensure that multi-factor authentication is enabled for all privileged users | 2 | 2H |
| [`3.1`](#ctrl-3-1) | Ensure that 'Secure transfer required' is set to 'Enabled' | 2 | 2H |
| [`3.7`](#ctrl-3-7) | Ensure default network access rule for storage accounts is set to deny | 1 | 1H |
| [`3.10`](#ctrl-3-10) | Ensure storage account access keys are periodically regenerated | 2 | 1H · 1L |
| [`3.12`](#ctrl-3-12) | Ensure storage for critical data is encrypted with Customer-Managed Key | 1 | 1M |
| [`5.1.2`](#ctrl-5-1-2) | Ensure Diagnostic Setting captures appropriate categories | 3 | 1H · 2M |
| [`5.1.5`](#ctrl-5-1-5) | Ensure that logging for Azure Key Vault is 'Enabled' | 2 | 2M |
| [`5.2.1`](#ctrl-5-2-1) | Ensure that Activity Log Alert exists for Create Policy Assignment | 2 | 1M · 1L |
| [`5.2.2`](#ctrl-5-2-2) | Ensure that Activity Log Alert exists for Delete Policy Assignment | 1 | 1M |
| [`5.2.4`](#ctrl-5-2-4) | Ensure that Activity Log Alert exists for Create or Update Network Security Group | 1 | 1M |
| [`8.1`](#ctrl-8-1) | Ensure that the expiration date is set on all keys | 2 | 2M |
| [`8.4`](#ctrl-8-4) | Ensure the Key Vault is recoverable | 2 | 2H |
| [`8.5`](#ctrl-8-5) | Enable role-based access control for Azure Key Vault | 2 | 2M |
| [`9.1`](#ctrl-9-1) | Ensure Container Registry has admin user disabled | 3 | 3H |
| [`9.2`](#ctrl-9-2) | Ensure Container Registry has content trust enabled | 2 | 1M · 1I |
| [`6.1`](#ctrl-6-1) | Ensure that RDP access from the Internet is evaluated and restricted | 1 | 1C |
| [`6.2`](#ctrl-6-2) | Ensure that SSH access from the Internet is evaluated and restricted | 1 | 1C |
| [`6.3`](#ctrl-6-3) | Ensure no Network Security Group allows unrestricted ingress to port 3389 | 3 | 1C · 1H · 1M |
| [`6.5`](#ctrl-6-5) | Ensure that Network Security Group flow log retention period is 'greater than 90 days' | 2 | 2M |
| [`6.6`](#ctrl-6-6) | Ensure that Network Watcher is 'Enabled' | 5 | 3H · 2M |
| [`9.3`](#ctrl-9-3) | Ensure that 'Web App Redirects All HTTP traffic to HTTPS' is set | 1 | 1H |
| [`9.4`](#ctrl-9-4) | Ensure Web App is using the latest version of TLS encryption | 1 | 1H |
| [`9.5`](#ctrl-9-5) | Ensure that Register with Azure AD is enabled on App Service | 1 | 1M |
| [`9.10`](#ctrl-9-10) | Ensure FTP deployments are Disabled | 1 | 1M |
| [`9.11`](#ctrl-9-11) | Ensure Azure Key Vaults are used to store secrets | 1 | 1H |
| [`4.1.1`](#ctrl-4-1-1) | Ensure that 'Auditing' is set to 'On' | 1 | 1H |
| [`4.1.3`](#ctrl-4-1-3) | Ensure that 'Data encryption' is set to 'On' for SQL databases | 1 | 1M |
| [`4.1.4`](#ctrl-4-1-4) | Ensure that 'Azure Active Directory Admin' is configured for SQL Servers | 1 | 1M |
| [`4.2.1`](#ctrl-4-2-1) | Ensure that Advanced Threat Protection (ATP) on a SQL Server is set to 'On' | 1 | 1M |
| [`7.1`](#ctrl-7-1) | Ensure Virtual Machines use Managed Disks | 1 | 1M |
| [`7.2`](#ctrl-7-2) | Ensure that OS and Data disks are encrypted with CMK | 1 | 1H |
| [`7.4`](#ctrl-7-4) | Ensure that only approved extensions are installed | 1 | 1M |

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

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-001`](../providers/azure_cloud.md) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ENTRA-005`](../providers/azure_cloud.md) | No Conditional Access policy restricting external users | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 1.1.1: Ensure Security Defaults are enabled on Azure Active Directory { #ctrl-1-1-1 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-003`](../providers/azure_cloud.md) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ENTRA-006`](../providers/azure_cloud.md) | No Conditional Access sign-in risk policy | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 1.1.2: Ensure that multi-factor authentication is enabled for all privileged users { #ctrl-1-1-2 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ENTRA-002`](../providers/azure_cloud.md) | App registration credential valid beyond 180 days | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ENTRA-004`](../providers/azure_cloud.md) | No Conditional Access policy requiring MFA for admins | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.1: Ensure that 'Secure transfer required' is set to 'Enabled' { #ctrl-3-1 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-002`](../providers/azure_cloud.md) | Storage account allows non-HTTPS traffic | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZST-004`](../providers/azure_cloud.md) | Storage account minimum TLS version below 1.2 | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.7: Ensure default network access rule for storage accounts is set to deny { #ctrl-3-7 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-001`](../providers/azure_cloud.md) | Storage account allows public blob access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.10: Ensure storage account access keys are periodically regenerated { #ctrl-3-10 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-005`](../providers/azure_cloud.md) | Storage account blob lifecycle policy should be reviewed | <span class="pg-sev pg-sev--low">LOW</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZST-006`](../providers/azure_cloud.md) | Storage account access keys not rotated within 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 3.12: Ensure storage for critical data is encrypted with Customer-Managed Key { #ctrl-3-12 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZST-003`](../providers/azure_cloud.md) | Storage account not encrypted with customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.1.2: Ensure Diagnostic Setting captures appropriate categories { #ctrl-5-1-2 }

**Evidenced by 3 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-001`](../providers/azure_cloud.md) | No diagnostic setting for subscription Activity Log | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-002`](../providers/azure_cloud.md) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-006`](../providers/azure_cloud.md) | Log Analytics workspace retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.1.5: Ensure that logging for Azure Key Vault is 'Enabled' { #ctrl-5-1-5 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-002`](../providers/azure_cloud.md) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-004`](../providers/azure_cloud.md) | Key Vault has no diagnostic settings configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 5.2.1: Ensure that Activity Log Alert exists for Create Policy Assignment { #ctrl-5-2-1 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-007`](../providers/azure_cloud.md) | No service health alert rule configured | <span class="pg-sev pg-sev--low">LOW</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

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

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AKV-004`](../providers/azure_cloud.md) | Key Vault key has no expiration date | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-005`](../providers/azure_cloud.md) | Key Vault secret has no expiration date | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 8.4: Ensure the Key Vault is recoverable { #ctrl-8-4 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AKV-001`](../providers/azure_cloud.md) | Key Vault soft delete not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-002`](../providers/azure_cloud.md) | Key Vault purge protection not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 8.5: Enable role-based access control for Azure Key Vault { #ctrl-8-5 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AKV-003`](../providers/azure_cloud.md) | Key Vault allows access from all networks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-006`](../providers/azure_cloud.md) | Key Vault uses vault access policies instead of RBAC | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.1: Ensure Container Registry has admin user disabled { #ctrl-9-1 }

**Evidenced by 3 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-001`](../providers/azure_cloud.md) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ACR-002`](../providers/azure_cloud.md) | Container registry allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ACR-004`](../providers/azure_cloud.md) | Container registry Defender scanning not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.2: Ensure Container Registry has content trust enabled { #ctrl-9-2 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-003`](../providers/azure_cloud.md) | Container registry content trust not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ACR-005`](../providers/azure_cloud.md) | Container registry tag immutability (verify per-repository locking) | <span class="pg-sev pg-sev--info">INFO</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 6.1: Ensure that RDP access from the Internet is evaluated and restricted { #ctrl-6-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZNW-001`](../providers/azure_cloud.md) | NSG allows inbound SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 6.2: Ensure that SSH access from the Internet is evaluated and restricted { #ctrl-6-2 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZNW-001`](../providers/azure_cloud.md) | NSG allows inbound SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 6.3: Ensure no Network Security Group allows unrestricted ingress to port 3389 { #ctrl-6-3 }

**Evidenced by 3 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZNW-001`](../providers/azure_cloud.md) | NSG allows inbound SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZNW-004`](../providers/azure_cloud.md) | NSG has no explicit deny-all inbound rule | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZSQL-003`](../providers/azure_cloud.md) | SQL Server allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 6.5: Ensure that Network Security Group flow log retention period is 'greater than 90 days' { #ctrl-6-5 }

**Evidenced by 2 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-005`](../providers/azure_cloud.md) | NSG flow log retention less than 90 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZNW-002`](../providers/azure_cloud.md) | NSG does not have flow logging enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 6.6: Ensure that Network Watcher is 'Enabled' { #ctrl-6-6 }

**Evidenced by 5 checks** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZNW-002`](../providers/azure_cloud.md) | NSG does not have flow logging enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZNW-003`](../providers/azure_cloud.md) | Application Gateway does not have WAF enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZNW-005`](../providers/azure_cloud.md) | Public IP address associated with a VM NIC | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZVM-002`](../providers/azure_cloud.md) | Virtual machine has a public IP address | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZVM-003`](../providers/azure_cloud.md) | Virtual machine does not have JIT network access | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.3: Ensure that 'Web App Redirects All HTTP traffic to HTTPS' is set { #ctrl-9-3 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZAPP-001`](../providers/azure_cloud.md) | App Service does not enforce HTTPS | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.4: Ensure Web App is using the latest version of TLS encryption { #ctrl-9-4 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZAPP-002`](../providers/azure_cloud.md) | App Service minimum TLS version below 1.2 | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.5: Ensure that Register with Azure AD is enabled on App Service { #ctrl-9-5 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZAPP-003`](../providers/azure_cloud.md) | App Service does not use a managed identity | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.10: Ensure FTP deployments are Disabled { #ctrl-9-10 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZAPP-005`](../providers/azure_cloud.md) | App Service FTP access not disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 9.11: Ensure Azure Key Vaults are used to store secrets { #ctrl-9-11 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZAPP-004`](../providers/azure_cloud.md) | App Service has remote debugging enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 4.1.1: Ensure that 'Auditing' is set to 'On' { #ctrl-4-1-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZSQL-002`](../providers/azure_cloud.md) | SQL Server auditing not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 4.1.3: Ensure that 'Data encryption' is set to 'On' for SQL databases { #ctrl-4-1-3 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZSQL-001`](../providers/azure_cloud.md) | SQL Server TDE does not use a customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 4.1.4: Ensure that 'Azure Active Directory Admin' is configured for SQL Servers { #ctrl-4-1-4 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZSQL-004`](../providers/azure_cloud.md) | SQL Server has no Azure AD administrator configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 4.2.1: Ensure that Advanced Threat Protection (ATP) on a SQL Server is set to 'On' { #ctrl-4-2-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZSQL-005`](../providers/azure_cloud.md) | SQL Server advanced threat protection not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 7.1: Ensure Virtual Machines use Managed Disks { #ctrl-7-1 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZVM-005`](../providers/azure_cloud.md) | Virtual machine does not use a managed identity | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 7.2: Ensure that OS and Data disks are encrypted with CMK { #ctrl-7-2 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZVM-001`](../providers/azure_cloud.md) | Virtual machine disks are not encrypted | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

### 7.4: Ensure that only approved extensions are installed { #ctrl-7-4 }

**Evidenced by 1 check** across Azure Cloud.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZVM-004`](../providers/azure_cloud.md) | Virtual machine automatic OS patching not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_azure_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_azure_foundations`._
