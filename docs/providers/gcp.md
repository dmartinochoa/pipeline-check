# GCP provider

Scans a live GCP project via the ``google-cloud-*`` client libraries.
Requires ``pip install pipeline-check[gcp]`` and Application Default
Credentials (``gcloud auth application-default login``).

## Producer workflow

```bash
pipeline_check --pipeline gcp --gcp-project my-project-id
pipeline_check --pipeline gcp --gcp-project $GCP_PROJECT
```

## Covered services

| Service | Prefix | Rules |
|---------|--------|-------|
| IAM | GCIAM- | Service account admin roles, user-managed keys, impersonation |
| Cloud Storage | GCS- | Public buckets, uniform access, versioning |
| Cloud KMS | GCKMS- | Key rotation, public access, HSM protection |
| Artifact Registry | GAR- | Vulnerability scanning, public repos, cleanup policies |
| Cloud Logging | GCLOG- | Audit log config, log sinks, retention |

## What it covers

50 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GAR-001](#gar-001) | Artifact Registry repository has no vulnerability scanning | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GAR-002](#gar-002) | Artifact Registry repository is publicly readable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GAR-003](#gar-003) | Artifact Registry has no cleanup policy | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCCE-001](#gcce-001) | Compute instance does not have Shielded VM enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCCE-002](#gcce-002) | Compute instance does not have OS Login enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCCE-003](#gcce-003) | Compute instance has serial port access enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCCE-004](#gcce-004) | Compute instance has an external IP address | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCCE-005](#gcce-005) | Instance does not block project-wide SSH keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCIAM-001](#gciam-001) | Service account has Owner or Editor role on project | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GCIAM-002](#gciam-002) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCIAM-003](#gciam-003) | Service account token creator granted without constraint | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCIAM-004](#gciam-004) | Compute instance uses default service account | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCIAM-005](#gciam-005) | Domain-restricted sharing constraint not enforced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCIAM-006](#gciam-006) | Service account key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCKMS-001](#gckms-001) | KMS key rotation period exceeds 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCKMS-002](#gckms-002) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCKMS-003](#gckms-003) | KMS key not using HSM protection level | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCKMS-004](#gckms-004) | KMS key ring IAM has overly broad bindings | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCKMS-005](#gckms-005) | KMS key has primary version scheduled for destruction | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCKMS-006](#gckms-006) | KMS key uses imported (external) key material | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCLOG-001](#gclog-001) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCLOG-002](#gclog-002) | No log sink configured for audit logs | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-003](#gclog-003) | Log bucket retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-004](#gclog-004) | VPC Flow Logs not enabled on subnet | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-005](#gclog-005) | Firewall rule logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-006](#gclog-006) | Critical service missing Data Access audit log types | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-007](#gclog-007) | No log metric filter for IAM policy changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-008](#gclog-008) | No log metric filter for firewall rule changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-009](#gclog-009) | No log metric filter for route changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-010](#gclog-010) | No log metric filter for Cloud SQL config changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-011](#gclog-011) | No log metric filter for custom role changes | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCNET-001](#gcnet-001) | Default VPC network exists in project | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCNET-002](#gcnet-002) | No default-deny ingress firewall rule configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCNET-003](#gcnet-003) | Firewall allows SSH or RDP from the internet | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GCNET-004](#gcnet-004) | Subnet does not have Private Google Access enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCNET-005](#gcnet-005) | No Cloud NAT gateway configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCRUN-001](#gcrun-001) | Cloud Run service allows unauthenticated access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCRUN-002](#gcrun-002) | Cloud Run service or function uses default compute SA | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCRUN-003](#gcrun-003) | Cloud Run service has zero minimum instances | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCRUN-004](#gcrun-004) | Cloud Run service does not use a VPC connector | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-001](#gcs-001) | Cloud Storage bucket is publicly accessible | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCS-002](#gcs-002) | Bucket does not enforce uniform bucket-level access | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-003](#gcs-003) | Bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-004](#gcs-004) | Cloud Storage bucket not encrypted with CMEK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-005](#gcs-005) | Cloud Storage bucket access logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCSQL-001](#gcsql-001) | Cloud SQL instance has a public IP address | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCSQL-002](#gcsql-002) | Cloud SQL instance does not have automated backups enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCSQL-003](#gcsql-003) | Cloud SQL instance does not require SSL connections | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCSQL-004](#gcsql-004) | Cloud SQL instance does not have IAM authentication enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCSQL-005](#gcsql-005) | Cloud SQL instance does not have point-in-time recovery enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GAR-001: Artifact Registry repository has no vulnerability scanning { #gar-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without vulnerability scanning, container images with known CVEs pass through the artifact store without detection.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable vulnerability scanning on the repository by configuring the Container Analysis / On-Demand Scanning API. Set the scanning config to STANDARD or enable Artifact Analysis at the project level.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GAR-002: Artifact Registry repository is publicly readable { #gar-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A publicly readable repository allows anyone to pull images. Internal images may contain proprietary code, configuration, or embedded credentials.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove allUsers and allAuthenticatedUsers from the repository's IAM policy. Use service accounts with artifactregistry.reader for authenticated access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GAR-003: Artifact Registry has no cleanup policy { #gar-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-459</span>
</div>

Without a cleanup policy, old image tags accumulate indefinitely. Stale images may contain known vulnerabilities and remain pullable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a cleanup policy on the repository to automatically delete old or unused artifacts. This reduces storage costs and limits the window in which a compromised old image can be pulled.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCCE-001: Compute instance does not have Shielded VM enabled { #gcce-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Shielded VM uses Secure Boot, vTPM, and integrity monitoring to defend against boot-level and kernel-level malware. Without it, an attacker who gains root can install a persistent rootkit that survives reboots.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Shielded VM with both vTPM and integrity monitoring on all Compute Engine instances. Shielded VM verifies the boot chain and detects boot-level rootkits.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCCE-002: Compute instance does not have OS Login enabled { #gcce-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

OS Login uses IAM to manage SSH access to instances instead of SSH keys stored in project or instance metadata. Without it, anyone who can edit metadata can inject an SSH key and gain shell access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the metadata key 'enable-oslogin' to 'TRUE' on every instance (or at the project level). OS Login ties SSH access to IAM, removing the need to manage SSH keys.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCCE-003: Compute instance has serial port access enabled { #gcce-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Enabling the interactive serial console (serial-port-enable) allows anyone with the compute.instances.getSerialPortOutput permission to read console output, which may contain boot logs, kernel messages, or application secrets.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the metadata key 'serial-port-enable' to 'false' (or remove it) on every instance. Use the Cloud Console or gcloud SSH instead for debugging.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCCE-004: Compute instance has an external IP address { #gcce-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

An external IP makes the instance directly addressable from the internet. Combined with a permissive firewall rule, this exposes the instance to scanning, brute-force attacks, and exploitation of any listening service.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove external IP addresses from instances that do not need direct internet access. Use Cloud NAT for outbound connectivity and IAP TCP forwarding for administrative access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCCE-005: Instance does not block project-wide SSH keys { #gcce-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Project-wide SSH keys are propagated to every instance that does not explicitly block them. An attacker who can edit project metadata can inject an SSH key and access all instances that accept project keys.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the metadata key 'block-project-ssh-keys' to 'TRUE' on instances that should not accept project-level SSH keys. This limits SSH access to keys defined on the instance itself or via OS Login.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GCIAM-001: Service account has Owner or Editor role on project { #gciam-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

The basic roles (Owner, Editor) predate IAM and grant extremely broad access. A compromised service account with roles/owner can modify IAM policies, delete resources, and exfiltrate data across the entire project.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the Owner/Editor binding with a scoped predefined or custom role that grants only the permissions the service account needs. roles/owner and roles/editor grant full or near-full access to every resource in the project.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCIAM-002: Service account has user-managed key { #gciam-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

User-managed service account keys are JSON files that act as permanent credentials. They don't expire by default, can be downloaded by anyone with the right IAM role, and are the most common GCP credential found in public leaks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Delete user-managed keys and use workload identity federation, attached service accounts, or the metadata server instead. User-managed keys are long-lived credentials that cannot be automatically rotated by GCP.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCIAM-003: Service account token creator granted without constraint { #gciam-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

roles/iam.serviceAccountTokenCreator allows a principal to mint OAuth2 tokens and sign JWTs as any service account in the project. A project-level grant without a condition is effectively a privilege-escalation vector.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict iam.serviceAccountTokenCreator bindings to specific service accounts using IAM conditions (resource.name == 'projects/-/serviceAccounts/TARGET'). Avoid project-level grants of this role.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCIAM-004: Compute instance uses default service account { #gciam-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

The Compute Engine default service account (*-compute@developer.gserviceaccount.com) is automatically granted the Editor role on the project. Any workload running under it inherits near-full access to every resource.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a dedicated service account with minimum required permissions for each workload. Replace the default compute service account on every instance.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCIAM-005: Domain-restricted sharing constraint not enforced { #gciam-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without the domain-restricted sharing constraint, any GCP user with sufficient IAM permissions can grant access to arbitrary external Google accounts, enabling data exfiltration or persistence by outside parties.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the iam.allowedPolicyMemberDomains organization policy constraint to limit IAM bindings to your corporate domain(s). This prevents accidental or malicious grants to external accounts.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCIAM-006: Service account key older than 90 days { #gciam-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

Long-lived service account keys increase the blast radius of a credential leak. CIS GCP Foundations recommends rotating user-managed keys at most every 90 days.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate or delete user-managed service account keys older than 90 days. Prefer workload identity federation to eliminate long-lived keys entirely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCKMS-001: KMS key rotation period exceeds 365 days { #gckms-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

Regular key rotation limits the window of exposure if a key version is compromised. CIS GCP Foundations requires rotation within 365 days for symmetric encryption keys.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the rotation period to 365 days or less. GCP automatically creates a new key version when the rotation period elapses.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCKMS-002: KMS key IAM policy grants public access { #gckms-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A KMS key with allUsers access allows anyone on the internet to encrypt, decrypt, or sign data with the key, depending on the granted role.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove allUsers and allAuthenticatedUsers from the key's IAM policy. KMS keys should only be accessible to service accounts that need them.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCKMS-003: KMS key not using HSM protection level { #gckms-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

SOFTWARE protection level keys are managed in software; HSM protection level keys are backed by Cloud HSM (FIPS 140-2 Level 3). HSM adds defense against certain insider and physical-access threats.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HSM (Hardware Security Module) protection level for keys that protect sensitive data. HSM keys never leave the hardware boundary.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCKMS-004: KMS key ring IAM has overly broad bindings { #gckms-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

KMS key ring IAM policies govern access to every key in the ring. An overly broad binding (allUsers, allAuthenticatedUsers) grants the entire internet access to encrypt, decrypt, or manage keys.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove allUsers, allAuthenticatedUsers, and overly broad domain-scoped members from KMS key ring IAM policies. Restrict key access to specific service accounts that need encrypt/decrypt/sign operations.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCKMS-005: KMS key has primary version scheduled for destruction { #gckms-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-324</span>
</div>

A key version scheduled for destruction will become permanently unavailable after the scheduled destroy time. Any data encrypted with that version becomes unrecoverable. This check flags keys where the primary version is pending destruction.

<div class="pg-rule__rec" markdown>

**Recommended action**

Review keys with DESTROY_SCHEDULED primary versions. If the key is still in use, cancel the destruction. If intentional, ensure all dependent services have migrated to a new key before the destruction window closes.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCKMS-006: KMS key uses imported (external) key material { #gckms-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

Keys with EXTERNAL or EXTERNAL_VPC protection level use key material imported from outside GCP. The security of these keys depends on the external key management infrastructure, which is outside GCP's control.

<div class="pg-rule__rec" markdown>

**Recommended action**

Document the key material import process and ensure the external key material is stored securely. Consider using GCP-generated key material (SOFTWARE or HSM protection level) unless regulatory requirements mandate external key management.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCLOG-001: Cloud Audit Logs not enabled for all services { #gclog-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Admin Activity logs are always on, but Data Access logs (reads and writes to user data) must be explicitly enabled. Without them, access to Cloud Storage objects, BigQuery datasets, and other data resources is invisible.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the project IAM policy's auditConfigs to enable Data Access audit logs for allServices. At minimum, enable ADMIN_READ and DATA_WRITE log types.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-002: No log sink configured for audit logs { #gclog-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Cloud Logging retains logs for a limited period (30 days by default for _Default bucket). A log sink exports logs to a destination with configurable retention, enabling forensic analysis months after an incident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log sink that exports audit logs to a durable destination (Cloud Storage, BigQuery, or Pub/Sub) for long-term retention and analysis.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-003: Log bucket retention less than 365 days { #gclog-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-779</span>
</div>

The default _Default log bucket retains logs for 30 days. Many compliance frameworks require at least one year of audit log retention.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the log bucket retention period to at least 365 days. For the _Default bucket, update the retention via gcloud logging buckets update.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-004: VPC Flow Logs not enabled on subnet { #gclog-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

VPC Flow Logs record a sample of network flows sent from and received by VM instances. Without them, lateral movement and data exfiltration over the network are invisible to security monitoring.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable VPC Flow Logs on all subnets. Flow logs capture a sample of network flows, enabling threat detection, traffic analysis, and compliance evidence.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-005: Firewall rule logging not enabled { #gclog-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Without firewall rule logging, allowed and denied connection attempts are invisible. Enabling logs on every rule creates an audit trail for traffic flowing through VPC firewalls.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable logging on all firewall rules. Firewall logs record connections allowed and denied by each rule, supporting incident investigation and compliance evidence.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-006: Critical service missing Data Access audit log types { #gclog-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

While enabling allServices audit logging is a good baseline, critical services like Storage, IAM, and Compute should have explicit per-service audit configs to ensure visibility is not accidentally removed by a broad policy change.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure per-service audit log configs for storage.googleapis.com, iam.googleapis.com, and compute.googleapis.com to include all three log types: ADMIN_READ (1), DATA_WRITE (2), and DATA_READ (3).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-007: No log metric filter for IAM policy changes { #gclog-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

IAM policy changes are high-impact actions. A log-based metric and alert ensures that unexpected privilege escalation or access grants trigger an immediate notification rather than going unnoticed in the audit log.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log-based metric with a filter matching IAM policy changes (e.g. resource.type="project" AND protoPayload.methodName="SetIamPolicy") and configure an alerting policy on it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-008: No log metric filter for firewall rule changes { #gclog-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Firewall rule changes can open unexpected ingress paths. A log-based metric and alert for firewall mutations catches accidental or malicious network policy changes in real time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log-based metric with a filter matching firewall rule changes (e.g. resource.type="gce_firewall_rule") and configure an alerting policy on it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-009: No log metric filter for route changes { #gclog-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Route changes can redirect network traffic through attacker-controlled instances. A log-based metric and alert for route mutations catches unauthorized traffic redirection attempts in real time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log-based metric with a filter matching route changes (e.g. resource.type="gce_route") and configure an alerting policy on it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-010: No log metric filter for Cloud SQL config changes { #gclog-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Cloud SQL configuration changes (disabling SSL, enabling public IP, modifying database flags) can weaken security. A log-based metric and alert for these mutations catches unauthorized database configuration changes.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log-based metric with a filter matching Cloud SQL configuration changes (e.g. protoPayload.methodName="cloudsql.instances.update") and configure an alerting policy on it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCLOG-011: No log metric filter for custom role changes { #gclog-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Custom role changes can grant new permissions or weaken existing access controls. A log-based metric and alert for custom role mutations catches privilege escalation via role modification.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a log-based metric with a filter matching custom role changes (e.g. resource.type="iam_role") and configure an alerting policy on it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCNET-001: Default VPC network exists in project { #gcnet-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Every new GCP project is created with a default network that includes auto-created subnets in every region and permissive firewall rules (allow SSH, RDP, ICMP from anywhere). Deleting it forces teams to create purpose-built networks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Delete the default VPC network and create custom networks with explicitly defined subnets and firewall rules. The default network includes pre-populated firewall rules that allow broad internal traffic.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCNET-002: No default-deny ingress firewall rule configured { #gcnet-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

GCP's implied firewall rules deny all ingress and allow all egress by default, but auto-created rules in the default network override this. An explicit deny-all ingress rule at low priority makes the deny posture visible and auditable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a low-priority (e.g. 65534) INGRESS DENY ALL rule for 0.0.0.0/0 on each VPC network. This ensures that only explicitly allowed traffic reaches instances.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GCNET-003: Firewall allows SSH or RDP from the internet { #gcnet-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Firewall rules allowing SSH or RDP from 0.0.0.0/0 expose instances to brute-force attacks and credential-stuffing from the entire internet. This is the most common initial access vector for cloud-hosted VMs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict SSH (tcp:22) and RDP (tcp:3389) firewall rules to specific source CIDR ranges (e.g. corporate VPN IPs). Use IAP TCP forwarding or OS Login instead of direct internet access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCNET-004: Subnet does not have Private Google Access enabled { #gcnet-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Without Private Google Access, instances that lack an external IP cannot reach Google APIs (Cloud Storage, BigQuery, etc.). Enabling it lets private instances access these services without exposing them to the internet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Private Google Access on all subnets so that instances without external IPs can still reach Google APIs and services over Google's internal network.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCNET-005: No Cloud NAT gateway configured { #gcnet-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Cloud NAT provides outbound internet connectivity for instances without external IPs. Without it, private instances are cut off from external repositories, update servers, and third-party APIs unless a proxy is configured.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a Cloud NAT gateway on at least one Cloud Router so that instances without external IPs can reach the internet for updates and package downloads without being directly addressable.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCRUN-001: Cloud Run service allows unauthenticated access { #gcrun-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A Cloud Run service with INGRESS_TRAFFIC_ALL allows any internet user to invoke it. If the service does not implement its own authentication, it is fully exposed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the Cloud Run service ingress to INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER, or require authentication via IAM invoker bindings. Public services should be behind a load balancer with IAP or API Gateway.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCRUN-002: Cloud Run service or function uses default compute SA { #gcrun-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Cloud Run services and Cloud Functions default to the Compute Engine default service account, which usually holds the Editor role. A compromised function running under this SA can access nearly every resource in the project.

<div class="pg-rule__rec" markdown>

**Recommended action**

Assign a dedicated service account with minimum required permissions to every Cloud Run service and Cloud Function. The default compute SA typically has the Editor role.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCRUN-003: Cloud Run service has zero minimum instances { #gcrun-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

A minimum instance count of zero means the service scales to zero when idle. The first request after idle incurs a cold start delay. For security-sensitive services (auth endpoints, webhook receivers), cold starts can cause timeouts that mask availability.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set min_instance_count to at least 1 for latency-sensitive services. Zero minimum instances cause cold starts on the first request after an idle period.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCRUN-004: Cloud Run service does not use a VPC connector { #gcrun-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without a VPC connector, Cloud Run services route egress traffic through the public internet. Services that access databases, caches, or internal APIs over the internet increase their attack surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a Serverless VPC Access connector on Cloud Run services that access internal resources. This routes egress traffic through the VPC, enabling private IP connectivity and firewall enforcement.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCS-001: Cloud Storage bucket is publicly accessible { #gcs-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A bucket with allUsers or allAuthenticatedUsers in its IAM policy is accessible to the internet. Build artifacts, Terraform state files, and deployment manifests stored in public buckets are trivially discoverable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove allUsers and allAuthenticatedUsers members from the bucket's IAM policy. Use signed URLs or IAM-authenticated access for legitimate public-facing content.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCS-002: Bucket does not enforce uniform bucket-level access { #gcs-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without uniform bucket-level access, objects can have individual ACLs that override bucket-level IAM policies. This creates an unauditable surface: a single object can be made public without changing the bucket policy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable uniform bucket-level access on the bucket. This disables object-level ACLs and enforces access exclusively through IAM, simplifying policy management and auditing.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCS-003: Bucket versioning not enabled { #gcs-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Without versioning, overwritten or deleted objects are permanently lost. Versioning makes every write and delete recoverable, protecting against accidental or malicious artifact replacement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable object versioning on the bucket. Combine with a lifecycle rule to delete old versions after a retention period to control storage costs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCS-004: Cloud Storage bucket not encrypted with CMEK { #gcs-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

By default GCP encrypts bucket data with Google-managed keys. CMEK adds an additional layer of control: you can revoke access to stored data by disabling the key, and key usage appears in Cloud Audit Logs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set a default Cloud KMS key on the bucket to use customer-managed encryption keys (CMEK). CMEK gives you control over the key lifecycle and access policy.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCS-005: Cloud Storage bucket access logging not enabled { #gcs-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Cloud Storage access logs capture object-level operations that Cloud Audit Logs may not cover in detail. Without access logging, it is difficult to determine who accessed or modified specific objects after a security incident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable access logging on the bucket by setting a log bucket destination. Access logs record every read and write, supporting forensic analysis and compliance audits.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCSQL-001: Cloud SQL instance has a public IP address { #gcsql-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A Cloud SQL instance with a public IP is directly reachable from the internet. Even with authorized networks configured, the attack surface is larger than a private-IP-only setup behind a VPC.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable the public IP on the Cloud SQL instance and use private IP with VPC peering or the Cloud SQL Auth Proxy for connectivity. If a public IP is required, restrict authorized networks to specific CIDR ranges.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCSQL-002: Cloud SQL instance does not have automated backups enabled { #gcsql-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Without automated backups, a destructive action (accidental DROP TABLE, ransomware, or a rogue admin) can cause permanent data loss. Automated backups provide a recovery point within the configured retention window.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable automated backups on every Cloud SQL instance. Automated backups protect against data loss from accidental deletion, corruption, or ransomware.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCSQL-003: Cloud SQL instance does not require SSL connections { #gcsql-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Without SSL enforcement, database connections can be intercepted on the network. An attacker with network access can capture credentials and query results in plaintext.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``ipConfiguration.sslMode`` to ``ENCRYPTED_ONLY`` (or ``TRUSTED_CLIENT_CERTIFICATE_REQUIRED`` for mTLS) on the Cloud SQL instance so all client connections are encrypted with TLS. ``sslMode`` is the modern control; the legacy ``requireSsl`` boolean maps only to the strict client-certificate mode.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCSQL-004: Cloud SQL instance does not have IAM authentication enabled { #gcsql-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

IAM database authentication ties database access to centrally managed IAM identities. Without it, database credentials are managed separately, increasing the risk of stale or shared passwords.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable IAM database authentication by setting the cloudsql.iam_authentication database flag to 'on'. This allows using IAM-managed identities instead of built-in database passwords.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCSQL-005: Cloud SQL instance does not have point-in-time recovery enabled { #gcsql-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Automated backups alone only allow recovery to the latest backup. Point-in-time recovery extends this to any second within the log retention window, reducing the recovery point objective (RPO) from hours to seconds.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable point-in-time recovery (PITR) on every Cloud SQL instance. PITR uses write-ahead logs to allow recovery to any point within the retention window, minimizing data loss.

</div>

</div>

---

## Adding a new GCP check

1. Create a new module at
   `pipeline_check/core/checks/gcp/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/gcp/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py gcp
   ```
