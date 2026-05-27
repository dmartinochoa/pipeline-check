# Azure Cloud provider

Scans a live Azure subscription via the ``azure-mgmt-*`` management
SDKs. Requires ``pip install pipeline-check[azure-cloud]`` and Azure
CLI authentication (``az login``).

## Producer workflow

```bash
pipeline_check --pipeline azure_cloud --subscription-id 00000000-0000-0000-0000-000000000000
pipeline_check --pipeline azure_cloud --subscription-id $AZURE_SUBSCRIPTION_ID --azure-tenant-id $AZURE_TENANT_ID
```

## Covered services

| Service | Prefix | Rules |
|---------|--------|-------|
| Entra ID (identity) | ENTRA- | Service principal roles, app credentials, password vs certificate |
| Storage | AZST- | Public access, HTTPS enforcement, CMK encryption |
| Key Vault | AKV- | Soft delete, purge protection, network ACLs |
| Container Registry | ACR- | Admin user, public access, content trust |
| Monitor | AZMON- | Diagnostic settings, log retention, alert rules |

## What it covers

50 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ACR-001](#acr-001) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ACR-002](#acr-002) | Container registry allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ACR-003](#acr-003) | Container registry content trust not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ACR-004](#acr-004) | Container registry Defender scanning not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ACR-005](#acr-005) | Container registry does not enforce tag immutability | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AKV-001](#akv-001) | Key Vault soft delete not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AKV-002](#akv-002) | Key Vault purge protection not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AKV-003](#akv-003) | Key Vault allows access from all networks | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AKV-004](#akv-004) | Key Vault key has no expiration date | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AKV-005](#akv-005) | Key Vault secret has no expiration date | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AKV-006](#akv-006) | Key Vault uses vault access policies instead of RBAC | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZAPP-001](#azapp-001) | App Service does not enforce HTTPS | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZAPP-002](#azapp-002) | App Service minimum TLS version below 1.2 | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZAPP-003](#azapp-003) | App Service does not use a managed identity | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZAPP-004](#azapp-004) | App Service has remote debugging enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZAPP-005](#azapp-005) | App Service FTP access not disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-001](#azmon-001) | No diagnostic setting for subscription Activity Log | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZMON-002](#azmon-002) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-003](#azmon-003) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-004](#azmon-004) | Key Vault has no diagnostic settings configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-005](#azmon-005) | NSG flow log retention less than 90 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-006](#azmon-006) | Log Analytics workspace retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-007](#azmon-007) | No service health alert rule configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [AZNW-001](#aznw-001) | NSG allows inbound SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [AZNW-002](#aznw-002) | NSG does not have flow logging enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZNW-003](#aznw-003) | Application Gateway does not have WAF enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZNW-004](#aznw-004) | NSG has no explicit deny-all inbound rule | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZNW-005](#aznw-005) | Public IP address associated with a VM NIC | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZSQL-001](#azsql-001) | SQL Server TDE does not use a customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZSQL-002](#azsql-002) | SQL Server auditing not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZSQL-003](#azsql-003) | SQL Server allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZSQL-004](#azsql-004) | SQL Server has no Azure AD administrator configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZSQL-005](#azsql-005) | SQL Server advanced threat protection not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZST-001](#azst-001) | Storage account allows public blob access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZST-002](#azst-002) | Storage account allows non-HTTPS traffic | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZST-003](#azst-003) | Storage account not encrypted with customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZST-004](#azst-004) | Storage account minimum TLS version below 1.2 | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZST-005](#azst-005) | Storage account has no blob lifecycle management policy | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [AZST-006](#azst-006) | Storage account access keys not rotated within 90 days | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZVM-001](#azvm-001) | Virtual machine disks are not encrypted | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZVM-002](#azvm-002) | Virtual machine has a public IP address | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZVM-003](#azvm-003) | Virtual machine does not have JIT network access | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZVM-004](#azvm-004) | Virtual machine automatic OS patching not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZVM-005](#azvm-005) | Virtual machine does not use a managed identity | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ENTRA-001](#entra-001) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ENTRA-002](#entra-002) | App registration credential valid beyond 180 days | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ENTRA-003](#entra-003) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ENTRA-004](#entra-004) | No Conditional Access policy requiring MFA for admins | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ENTRA-005](#entra-005) | No Conditional Access policy restricting external users | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ENTRA-006](#entra-006) | No Conditional Access sign-in risk policy | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ACR-001: Container registry admin user enabled { #acr-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

The ACR admin user is a single shared credential with full push/pull/delete access. It cannot be scoped, audited per identity, or protected with conditional access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable the admin user on the container registry and use Azure AD-based authentication (managed identities, service principals, or repository-scoped tokens) instead.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ACR-002: Container registry allows public network access { #acr-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A publicly accessible registry exposes the authentication endpoint to brute-force attempts and the image catalog to enumeration. Private endpoints restrict access to the VNet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable public network access on the container registry and use private endpoints or service endpoints for access from CI/CD pipelines and deployment targets.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ACR-003: Container registry content trust not enabled { #acr-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Without content trust, any authenticated principal can push an image tag. An attacker who compromises push credentials can replace a production image with a malicious one.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable content trust on the container registry. Content trust uses Notary v2 to sign images, ensuring only signed images can be pulled.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ACR-004: Container registry Defender scanning not enabled { #acr-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Without vulnerability scanning, container images with known CVEs flow through the CI/CD pipeline into production. Defender for Containers provides both push-time and continuous scanning.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Microsoft Defender for Containers on the subscription and configure the quarantine policy on Premium-tier registries. Defender scans images for OS and language-level vulnerabilities on push and import.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ACR-005: Container registry does not enforce tag immutability { #acr-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Without tag immutability, an attacker (or an accidental push) can overwrite a production image tag with a different image. Consumers pulling by tag receive the new, potentially malicious, content.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable tag immutability on the container registry. Immutable tags prevent overwriting an existing image tag, ensuring that a deployed tag always resolves to the same digest.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AKV-001: Key Vault soft delete not enabled { #akv-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-404</span>
</div>

Without soft delete, a deleted Key Vault (and all its keys, secrets, and certificates) is permanently lost. Soft delete retains the vault for a configurable retention period, enabling recovery from accidental or malicious deletion.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable soft delete on the Key Vault. As of Azure API version 2021-06-01-preview, soft delete is enforced on new vaults. For older vaults, enable it via the portal or CLI.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AKV-002: Key Vault purge protection not enabled { #akv-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-404</span>
</div>

Soft delete alone allows a sufficiently privileged identity to purge a vault before the retention period expires. Purge protection makes the retention period mandatory, closing the insider-threat vector.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable purge protection on the Key Vault. Purge protection prevents permanent deletion even by privileged administrators during the soft-delete retention period.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AKV-003: Key Vault allows access from all networks { #akv-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

The default Key Vault firewall allows access from all networks. Restricting to known VNets and IPs limits the attack surface for credential theft and key exfiltration.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the Key Vault firewall default action to 'Deny' and add explicit network rules for trusted VNets, IPs, or private endpoints.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AKV-004: Key Vault key has no expiration date { #akv-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

Keys without an expiration date never trigger rotation reminders or policy violations. A compromised key stays valid until manually revoked, widening the blast radius.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set an expiration date on all Key Vault keys. Rotate keys before expiration using automated rotation policies. Keys without expiration remain valid indefinitely if compromised.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AKV-005: Key Vault secret has no expiration date { #akv-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

Secrets without an expiration date never trigger rotation. A leaked API key or connection string stored without expiry remains usable until someone manually disables it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set an expiration date on all Key Vault secrets. Use automated rotation (Azure Key Vault rotation policies or Event Grid triggers) to rotate secrets before expiration.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AKV-006: Key Vault uses vault access policies instead of RBAC { #akv-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Vault access policies are tenant-wide and do not support conditions, PIM activation, or Conditional Access. Migrating to RBAC aligns Key Vault access with the rest of the Azure control plane.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable RBAC authorization on the Key Vault. RBAC authorization uses Azure AD roles with fine-grained permissions and inherits Conditional Access policies, replacing the legacy vault access policy model.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZAPP-001: App Service does not enforce HTTPS { #azapp-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Without HTTPS-only mode, clients can connect over HTTP and transmit authentication tokens, API keys, and application data in cleartext. This is exploitable on shared or compromised networks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable 'HTTPS Only' on the App Service. This redirects all HTTP traffic to HTTPS, preventing data from being transmitted in cleartext.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZAPP-002: App Service minimum TLS version below 1.2 { #azapp-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-326</span>
</div>

App Services that accept TLS 1.0 or 1.1 are vulnerable to protocol downgrade attacks. Enforcing TLS 1.2 as the floor prevents clients from negotiating weaker ciphers.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the App Service minimum TLS version to 1.2 (or higher). TLS 1.0 and 1.1 have known weaknesses and are deprecated across most compliance frameworks.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZAPP-003: App Service does not use a managed identity { #azapp-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Without a managed identity, the App Service must store connection strings, client secrets, or certificates in application settings or Key Vault references. Managed identities provide automatic credential rotation and eliminate secret sprawl.

<div class="pg-rule__rec" markdown>

**Recommended action**

Assign a system-assigned or user-assigned managed identity to the App Service. Managed identities eliminate the need for stored credentials when accessing Azure resources.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZAPP-004: App Service has remote debugging enabled { #azapp-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-489</span>
</div>

Remote debugging exposes a debug endpoint that accepts incoming connections. In production, this is an unnecessary attack surface. Azure automatically disables remote debugging after 48 hours, but it can be re-enabled.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable remote debugging on the App Service. Remote debugging opens additional ports and reduces the security posture of the app. Use Application Insights or log streaming for production diagnostics.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZAPP-005: App Service FTP access not disabled { #azapp-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

FTP deployment is a legacy mechanism that sends files and credentials unencrypted. FTPS (FTP over TLS) is acceptable but disabling FTP entirely is preferred.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the App Service FTP state to 'Disabled' or 'FtpsOnly'. Plain FTP transmits credentials and file contents in cleartext. Prefer deployment via Azure DevOps, GitHub Actions, or the Kudu ZIP API.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZMON-001: No diagnostic setting for subscription Activity Log { #azmon-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

The Activity Log records control-plane operations (role assignments, resource creation, policy changes). Without a diagnostic setting, these events are retained for only 90 days and are not queryable in Log Analytics.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a diagnostic setting on the subscription that sends Activity Log events to a Log Analytics workspace, Storage account, or Event Hub. Enable the Administrative, Security, and Policy categories at minimum.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZMON-002: Activity Log retention less than 365 days { #azmon-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-779</span>
</div>

Many compliance frameworks (PCI DSS, SOC 2) require at least one year of audit log retention. A short retention period limits forensic capability after a security incident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the diagnostic setting's destination (Log Analytics workspace or Storage account) with a retention period of at least 365 days.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZMON-003: No alert rule for critical administrative operations { #azmon-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Activity log alerts provide near-real-time notification of control-plane changes. Without them, infrastructure modifications (new role assignments, NSG changes) go unnoticed until the next manual audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create activity log alert rules for high-impact operations: policy assignment changes, role assignment changes, security group modifications, and Key Vault access policy changes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZMON-004: Key Vault has no diagnostic settings configured { #azmon-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Key Vault audit logs are the primary mechanism for detecting unauthorized secret access. Without diagnostic settings, access events are not retained beyond the Azure platform default and cannot be queried or alerted on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable diagnostic settings on each Key Vault to send AuditEvent logs to a Log Analytics workspace. These logs record every secret read, key use, and access policy change.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZMON-005: NSG flow log retention less than 90 days { #azmon-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-779</span>
</div>

Short flow log retention periods limit the ability to investigate lateral movement and data exfiltration. Compliance frameworks typically require at least 90 days of network log retention.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set NSG flow log retention to at least 90 days. Longer retention enables forensic analysis of network traffic patterns during incident investigations.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZMON-006: Log Analytics workspace retention less than 365 days { #azmon-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-779</span>
</div>

The default Log Analytics retention is 30 days. Audit logs and security events retained for less than 365 days may be unavailable during post-incident investigations.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the Log Analytics workspace retention to at least 365 days. Many compliance frameworks (PCI DSS, SOC 2) require one year of log retention for forensic readiness.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## AZMON-007: No service health alert rule configured { #azmon-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Service health alerts notify teams of Azure outages, degradations, and planned maintenance. Without them, pipeline failures caused by Azure platform issues are indistinguishable from application bugs until manually investigated.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create an activity log alert rule that monitors the 'ServiceHealth' category. Configure notifications for service issues, planned maintenance, and health advisories affecting your subscription.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## AZNW-001: NSG allows inbound SSH or RDP from the internet { #aznw-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Unrestricted SSH and RDP from the internet are the top entry vector for compromised VMs. Automated scanners continuously probe these ports, and a weak or leaked credential grants immediate shell access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove or restrict NSG rules that allow inbound access on ports 22 (SSH) and 3389 (RDP) from any source. Use Azure Bastion, JIT VM access, or a VPN gateway for administrative access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZNW-002: NSG does not have flow logging enabled { #aznw-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

NSG flow logs record network traffic metadata (source, destination, port, protocol, action). Without them, incident responders have no visibility into lateral movement or data exfiltration paths.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable NSG flow logs for every network security group. Send flow logs to a Storage account and optionally to a Log Analytics workspace for Traffic Analytics.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZNW-003: Application Gateway does not have WAF enabled { #aznw-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Application Gateways without WAF pass all HTTP traffic directly to backend pools. Attacks against web applications behind the gateway are not inspected or blocked.

<div class="pg-rule__rec" markdown>

**Recommended action**

Deploy Application Gateways with the WAF_v2 SKU and attach a WAF policy in Prevention mode. WAF protects web-facing applications from OWASP Top 10 attacks (SQL injection, XSS, request smuggling).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZNW-004: NSG has no explicit deny-all inbound rule { #aznw-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Azure NSGs include an implicit deny-all at priority 65500, but it is invisible in portal and audit exports. An explicit deny-all at a lower priority (e.g. 4096) documents the security intent and is visible in compliance reports.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an explicit deny-all inbound rule at the lowest priority in the NSG. While Azure NSGs have an implicit deny, an explicit rule makes the intent visible, auditable, and prevents accidental over-permissive rules from dominating.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZNW-005: Public IP address associated with a VM NIC { #aznw-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A public IP on a VM NIC exposes the VM directly to the internet. Combined with a permissive NSG, this creates a direct attack path to build agents and pipeline infrastructure.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove public IP addresses from VM network interfaces. Use Azure Bastion, a load balancer, or a VPN/ExpressRoute gateway for inbound connectivity. For outbound traffic, use NAT Gateway.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZSQL-001: SQL Server TDE does not use a customer-managed key { #azsql-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

By default, Azure SQL uses service-managed TDE keys. Customer-managed keys (CMK/BYOK) add a control plane: you can revoke the key to render the database unreadable, and key access events are logged in Key Vault diagnostics.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure Transparent Data Encryption (TDE) with a customer-managed key stored in Azure Key Vault. This gives you control over key rotation, revocation, and auditing.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZSQL-002: SQL Server auditing not enabled { #azsql-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Without auditing, database operations go unrecorded. Incident response teams cannot determine what data was accessed or modified after a breach.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable blob auditing on the SQL Server. Send audit logs to a Storage account and optionally to a Log Analytics workspace. Auditing records all database events including login attempts, queries, and schema changes.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZSQL-003: SQL Server allows public network access { #azsql-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A SQL Server with public network access enabled exposes its TDS endpoint to the internet. Combined with weak authentication or a SQL injection vector, this provides a direct path to the database.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable public network access on the SQL Server and use private endpoints for connectivity. If public access is required temporarily, restrict firewall rules to specific IP ranges.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZSQL-004: SQL Server has no Azure AD administrator configured { #azsql-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Without an Azure AD administrator, the SQL Server relies solely on SQL authentication (username/password). SQL credentials cannot be protected by MFA or Conditional Access policies.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure an Azure AD administrator on the SQL Server. Azure AD authentication supports MFA, Conditional Access, and centralized identity management. Consider disabling SQL authentication entirely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZSQL-005: SQL Server advanced threat protection not enabled { #azsql-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Advanced Threat Protection provides behavioral analytics on database activity. Without it, SQL injection attempts and credential stuffing attacks are not detected in real time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Advanced Threat Protection (ATP) on the SQL Server. ATP detects anomalous activities indicating potential SQL injection, brute-force attacks, and data exfiltration.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZST-001: Storage account allows public blob access { #azst-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

When blob public access is enabled at the account level, individual containers can be configured for anonymous read access. Artifacts, build logs, and SBOM files stored in publicly accessible containers are exposed to the internet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set 'Allow Blob public access' to disabled on the storage account. Use SAS tokens or Azure AD RBAC for legitimate access patterns.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZST-002: Storage account allows non-HTTPS traffic { #azst-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Without the secure-transfer flag, data in transit (including artifacts, secrets, and pipeline state) can be intercepted on shared networks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable 'Secure transfer required' on the storage account to reject all HTTP requests. All modern Azure SDKs and tools default to HTTPS.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZST-003: Storage account not encrypted with customer-managed key { #azst-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Azure encrypts all storage data at rest by default with Microsoft-managed keys. Customer-managed keys add an additional control plane: you can revoke the key to render data unreadable, and key access is auditable via Key Vault diagnostic logs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the storage account to use a customer-managed key (CMK) stored in Azure Key Vault. This gives you control over key rotation and revocation.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZST-004: Storage account minimum TLS version below 1.2 { #azst-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-326</span>
</div>

Storage accounts that accept TLS 1.0 or 1.1 expose data in transit to downgrade attacks. Azure supports TLS 1.2 as the minimum; enforcing it prevents clients from negotiating weaker protocol versions.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the storage account's minimum TLS version to TLS1_2. TLS 1.0 and 1.1 have known cryptographic weaknesses and are deprecated by most compliance frameworks.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## AZST-005: Storage account has no blob lifecycle management policy { #azst-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-404</span>
</div>

Without lifecycle management, build artifacts, logs, and temporary blobs accumulate indefinitely. Stale data increases the attack surface and complicates data-retention compliance.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a lifecycle management policy on the storage account to automatically transition or delete stale blobs. This limits the exposure window for old artifacts and reduces storage costs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZST-006: Storage account access keys not rotated within 90 days { #azst-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

Storage account keys are long-lived shared secrets with full read/write access. If a key is leaked in a CI/CD log or environment variable, an attacker retains access until the key is manually rotated.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate storage account access keys at least every 90 days. Use Azure Key Vault to manage key rotation automatically, or switch to Azure AD-based authentication to eliminate shared keys entirely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZVM-001: Virtual machine disks are not encrypted { #azvm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Unencrypted VM disks expose data to offline attacks. An attacker who gains access to the storage account backing a VM can mount the VHD and read all data, including pipeline agent credentials and build artifacts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Azure Disk Encryption (ADE) or server-side encryption with customer-managed keys on all VM OS and data disks. This protects data at rest from offline attacks on the underlying storage.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## AZVM-002: Virtual machine has a public IP address { #azvm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

VMs with public IP addresses are directly reachable from the internet. Build agents, pipeline controllers, and other CI/CD infrastructure should operate on private networks only.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove public IP addresses from VM network interfaces. Use Azure Bastion for administrative access and private endpoints or internal load balancers for service traffic.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZVM-003: Virtual machine does not have JIT network access { #azvm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

JIT access reduces the VM's attack surface by closing management ports (SSH, RDP) until they are explicitly requested. Without JIT, these ports remain open continuously even when no administrator needs access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Just-in-Time (JIT) VM access through Microsoft Defender for Cloud. JIT locks down inbound ports and opens them only when an authorized user requests access, for a limited time and from a specific IP.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZVM-004: Virtual machine automatic OS patching not enabled { #azvm-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span>
</div>

Build agent VMs and pipeline infrastructure without automatic patching accumulate unpatched vulnerabilities. An unpatched OS is the most common entry point for privilege escalation after initial access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable automatic OS patching on the virtual machine. For Windows VMs, enable 'EnableAutomaticUpdates'. For Linux VMs, set the patch mode to 'AutomaticByPlatform' and enable automatic assessment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## AZVM-005: Virtual machine does not use a managed identity { #azvm-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Build agent VMs without managed identities must store service principal credentials, storage keys, or connection strings locally. These static credentials can be extracted from the VM's file system, environment variables, or metadata service if compromised.

<div class="pg-rule__rec" markdown>

**Recommended action**

Assign a system-assigned or user-assigned managed identity to the virtual machine. Managed identities eliminate the need to store credentials on the VM for accessing Azure resources.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ENTRA-001: Service principal assigned Global Administrator { #entra-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Global Administrator is the highest-privilege directory role in Entra ID. A compromised service principal with this role can create users, reset passwords, modify conditional access, and escalate across the entire tenant.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the Global Administrator assignment with a scoped application role (Application Administrator, Cloud Application Administrator, or a custom role with least-privilege permissions). Service principals should never hold directory-wide admin rights.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ENTRA-002: App registration credential valid beyond 180 days { #entra-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-262</span>
</div>

Long-lived app credentials increase the blast radius of a leak. Microsoft recommends credential lifetimes of 180 days or less; CIS Azure Foundations requires expiry review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set credential expiry to 90 days or less and rotate before expiration. Use certificate credentials or managed identities instead of client secrets where possible.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ENTRA-003: Service principal uses password credential { #entra-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Password credentials (client secrets) are string tokens that can be copy-pasted, logged, or leaked. Certificate credentials bind to a key pair; the private key never leaves the host.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace client-secret (password) credentials with certificate credentials or managed identities. Certificate authentication eliminates the risk of secret leakage in logs, environment variables, or pipeline definitions.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ENTRA-004: No Conditional Access policy requiring MFA for admins { #entra-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-308</span>
</div>

Admin accounts are the highest-value targets in Entra ID. Without an MFA requirement enforced through Conditional Access, a single stolen password grants full tenant control.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a Conditional Access policy that requires multi-factor authentication for all users assigned directory admin roles (Global Administrator, Privileged Role Administrator, etc.).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ENTRA-005: No Conditional Access policy restricting external users { #entra-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

External (B2B guest) users inherit broad default permissions in Entra ID unless Conditional Access policies explicitly limit them. A compromised partner account can enumerate directory objects and access shared applications.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a Conditional Access policy that restricts guest and external user access. Require MFA, limit session lifetime, or block access to sensitive applications for external identities.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ENTRA-006: No Conditional Access sign-in risk policy { #entra-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-308</span>
</div>

Sign-in risk policies use machine-learning signals (unfamiliar location, impossible travel, anonymous IP) to detect credential compromise in real time. Without a risk-based policy, these signals are generated but never acted on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a Conditional Access policy that evaluates sign-in risk. For medium and high risk levels, require MFA or block the sign-in. This uses Entra ID Protection signals to detect anomalous logins.

</div>

</div>

---

## Adding a new Azure Cloud check

1. Create a new module at
   `pipeline_check/core/checks/azure_cloud/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/azure_cloud/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py azure_cloud
   ```
