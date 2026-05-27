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

15 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GAR-001](#gar-001) | Artifact Registry repository has no vulnerability scanning | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GAR-002](#gar-002) | Artifact Registry repository is publicly readable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GAR-003](#gar-003) | Artifact Registry has no cleanup policy | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCIAM-001](#gciam-001) | Service account has Owner or Editor role on project | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GCIAM-002](#gciam-002) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCIAM-003](#gciam-003) | Service account token creator granted without constraint | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCKMS-001](#gckms-001) | KMS key rotation period exceeds 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCKMS-002](#gckms-002) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCKMS-003](#gckms-003) | KMS key not using HSM protection level | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCLOG-001](#gclog-001) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCLOG-002](#gclog-002) | No log sink configured for audit logs | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCLOG-003](#gclog-003) | Log bucket retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-001](#gcs-001) | Cloud Storage bucket is publicly accessible | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCS-002](#gcs-002) | Bucket does not enforce uniform bucket-level access | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCS-003](#gcs-003) | Bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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
