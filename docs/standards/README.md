# Compliance standards

Every finding produced by the scanner carries a list of `ControlRef`
objects: references to controls in registered compliance standards. The
same check can evidence controls in multiple standards at once.

<div class="pg-doc-cards">
  <a class="pg-doc-card pg-doc-card--featured" href="owasp_cicd_top_10/">
    <span class="pg-doc-card__tag pg-doc-card__tag--accent">flagship · 10/10</span>
    <h3>OWASP Top 10 CI/CD</h3>
    <p>The reference framework for CI/CD security risks. Full coverage across every supported provider.</p>
    <span class="pg-doc-card__meta">{{ standards.owasp_cicd_top_10.controls }} controls · {{ standards.owasp_cicd_top_10.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="cis_aws_foundations/">
    <h3>CIS AWS Foundations</h3>
    <p>CI/CD-relevant subset of the CIS AWS benchmark. IAM, S3, CloudTrail, KMS hardening.</p>
    <span class="pg-doc-card__meta">{{ standards.cis_aws_foundations.controls }} controls · {{ standards.cis_aws_foundations.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="cis_github/">
    <h3>CIS GitHub Benchmark</h3>
    <p>Platform-side posture for a GitHub org or repo. Sections 1.1 (Code Changes), 1.4 (Third-Party), 1.5 (Code Risks).</p>
    <span class="pg-doc-card__meta">{{ standards.cis_github.controls }} controls · {{ standards.cis_github.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="cis_kubernetes/">
    <h3>CIS Kubernetes</h3>
    <p>CIS Kubernetes Benchmark, Section 5 (Policies). RBAC, Pod Security Standards, NetworkPolicy, Secrets, namespaces.</p>
    <span class="pg-doc-card__meta">{{ standards.cis_kubernetes.controls }} controls · {{ standards.cis_kubernetes.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="cis_supply_chain/">
    <h3>CIS Supply Chain</h3>
    <p>CIS Software Supply Chain Security Guide. Source, build, dependency, and artifact controls.</p>
    <span class="pg-doc-card__meta">{{ standards.cis_supply_chain.controls }} controls · {{ standards.cis_supply_chain.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="nist_ssdf/">
    <h3>NIST SSDF</h3>
    <p>Secure Software Development Framework, the federal SSDLC reference (SP 800-218).</p>
    <span class="pg-doc-card__meta">{{ standards.nist_ssdf.controls }} controls · {{ standards.nist_ssdf.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="nist_800_53/">
    <h3>NIST 800-53</h3>
    <p>Federal control catalog (CI/CD subset). Maps findings to AC, AU, CM, IA, SI, SR families.</p>
    <span class="pg-doc-card__meta">{{ standards.nist_800_53.controls }} controls · {{ standards.nist_800_53.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="nist_csf_2/">
    <h3>NIST CSF 2.0</h3>
    <p>Cybersecurity Framework. Govern, Identify, Protect, Detect, Respond, Recover.</p>
    <span class="pg-doc-card__meta">{{ standards.nist_csf_2.controls }} controls · {{ standards.nist_csf_2.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="nist_800_190/">
    <h3>NIST 800-190</h3>
    <p>Application Container Security Guide, image, registry, runtime, host hardening.</p>
    <span class="pg-doc-card__meta">{{ standards.nist_800_190.controls }} controls · {{ standards.nist_800_190.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="slsa/">
    <h3>SLSA Build Track</h3>
    <p>Supply-chain Levels for Software Artifacts. Provenance, hermeticity, signing posture.</p>
    <span class="pg-doc-card__meta">{{ standards.slsa.controls }} controls · {{ standards.slsa.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="pci_dss_v4/">
    <h3>PCI DSS v4.0</h3>
    <p>Payment Card Industry Data Security Standard, CI/CD subset (logging, secret management, change control).</p>
    <span class="pg-doc-card__meta">{{ standards.pci_dss_v4.controls }} controls · {{ standards.pci_dss_v4.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="esf_supply_chain/">
    <h3>NSA/CISA ESF</h3>
    <p>Enduring Security Framework. Securing the Software Supply Chain (developer, customer, supplier).</p>
    <span class="pg-doc-card__meta">{{ standards.esf_supply_chain.controls }} controls · {{ standards.esf_supply_chain.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="openssf_scorecard/">
    <h3>OpenSSF Scorecard</h3>
    <p>Open-source project security health metrics. Pinned-deps, branch-protection, signing-keys, dangerous workflows.</p>
    <span class="pg-doc-card__meta">{{ standards.openssf_scorecard.controls }} controls · {{ standards.openssf_scorecard.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="s2c2f/">
    <h3>S2C2F</h3>
    <p>Secure Supply Chain Consumption Framework, ingest, inventory, scan, rebuild, fix.</p>
    <span class="pg-doc-card__meta">{{ standards.s2c2f.controls }} controls · {{ standards.s2c2f.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="oscr/">
    <h3>OSC&amp;R</h3>
    <p>Open Software Supply Chain Attack Reference. MITRE ATT&amp;CK-style matrix for software supply chain attacks: 12 tactics, 86 techniques.</p>
    <span class="pg-doc-card__meta">{{ standards.oscr.controls }} controls · {{ standards.oscr.checks }} checks evidenced</span>
  </a>
  <a class="pg-doc-card" href="soc2/">
    <h3>SOC 2</h3>
    <p>Trust Services Criteria. Audit-friendly mappings for Security, Confidentiality, and Availability.</p>
    <span class="pg-doc-card__meta">{{ standards.soc2.controls }} controls · {{ standards.soc2.checks }} checks evidenced</span>
  </a>
</div>

## How to read severity

Every check ships at a fixed severity level. The scale is the same
across providers and standards, so a CRITICAL finding in one place
means the same thing as a CRITICAL finding anywhere else. Each
standards page links back here rather than restating the table.

| Level | What it means | Examples |
|-------|---------------|----------|
| <span class="pg-sev pg-sev--critical">CRITICAL</span> | Active exploit primitive in the workflow as written. Treat as P0: a default scan path lands an attacker on a secret, an RCE, or production write access without further effort. | Hardcoded credential literal, branch ref pointing at a known-compromised action, signed-into-an-unverified registry. |
| <span class="pg-sev pg-sev--high">HIGH</span> | Production-impact gap that requires modest attacker effort or a second condition to weaponize. Remediate this sprint; the secondary condition is usually already present in real pipelines. | Action pinned to a floating tag, sensitive permissions on a low-popularity action, mutable container tag in prod. |
| <span class="pg-sev pg-sev--medium">MEDIUM</span> | Significant defense-in-depth gap. Not directly exploitable on its own but disables a control whose absence widens the blast radius of a separate compromise. Backlog with a deadline. | Missing branch protection, container without resource limits, freshly-published dependency consumed before the cooldown window. |
| <span class="pg-sev pg-sev--low">LOW</span> | Hygiene / hardening issue. Not a vulnerability on its own but raises baseline posture and reduces audit friction. | Missing CI logging retention, SBOM without supplier attribution, ECR repo without scan-on-push. |
| <span class="pg-sev pg-sev--info">INFO</span> | Degraded-mode signal. The scanner couldn't reach an API or parse a config and surfaces the gap so the operator knows coverage was incomplete. No finding against the workload itself. | ``CB-000`` CodeBuild API access failed, ``IAM-000`` IAM enumeration failed. |

## Using standards at runtime

```bash
pipeline_check --list-standards                                                 # list registered standards
pipeline_check --pipeline aws --standard owasp_cicd_top_10                      # filter to one
pipeline_check --pipeline aws --standard owasp_cicd_top_10 --standard nist_ssdf # multiple
```

Omit `--standard` to include every registered standard.

## Architecture

A standard is pure data, no code. Each one is a Python module in
`pipeline_check/core/standards/data/` that defines a module-level `STANDARD`
object:

```python
from ..base import Standard

STANDARD = Standard(
    name="my_standard",
    title="My Compliance Standard",
    version="1.0",
    url="https://example.com",
    controls={
        "CTRL-1": "First control",
        ...
    },
    mappings={
        # check_id → list of control_ids it evidences
        "IAM-001": ["CTRL-1"],
        ...
    },
)
```

Register it in `pipeline_check/core/standards/__init__.py` and the scanner,
CLI (`--standard`, `--list-standards`), and reporters pick it up
automatically.

### Why data, not code

- **Re-use across checks:** a single check like `S3-002` can evidence
  multiple standards (OWASP CICD-SEC-9 *and* CIS 2.1.1) without the check
  itself knowing about any standard.
- **Easy to audit:** the mapping table lives in one file, not scattered
  across Finding constructor calls.
- **Easy to extend:** adding ISO 27001 or a bespoke internal policy is
  one new Python module.
