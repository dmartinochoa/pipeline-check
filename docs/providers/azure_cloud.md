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

15 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ACR-001](#acr-001) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ACR-002](#acr-002) | Container registry allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ACR-003](#acr-003) | Container registry content trust not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AKV-001](#akv-001) | Key Vault soft delete not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AKV-002](#akv-002) | Key Vault purge protection not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AKV-003](#akv-003) | Key Vault allows access from all networks | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-001](#azmon-001) | No diagnostic setting for subscription Activity Log | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZMON-002](#azmon-002) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZMON-003](#azmon-003) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [AZST-001](#azst-001) | Storage account allows public blob access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZST-002](#azst-002) | Storage account allows non-HTTPS traffic | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [AZST-003](#azst-003) | Storage account not encrypted with customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ENTRA-001](#entra-001) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ENTRA-002](#entra-002) | App registration credential valid beyond 180 days | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ENTRA-003](#entra-003) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
