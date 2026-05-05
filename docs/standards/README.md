# Compliance standards

Every finding produced by the scanner carries a list of `ControlRef` objects
— references to controls in registered compliance standards. The same check
can evidence controls in multiple standards at once.

<div class="pg-doc-cards" markdown>

<a class="pg-doc-card pg-doc-card--featured" href="owasp_cicd_top_10/" markdown>
<span class="pg-doc-card__tag pg-doc-card__tag--accent">flagship · 10/10</span>
<h3>OWASP Top 10 CI/CD</h3>
<p>The reference framework for CI/CD security risks. Full coverage across every supported provider.</p>
</a>

<a class="pg-doc-card" href="cis_aws_foundations/" markdown>
<h3>CIS AWS Foundations</h3>
<p>CI/CD-relevant subset of the CIS AWS benchmark — IAM, S3, CloudTrail, KMS hardening.</p>
</a>

<a class="pg-doc-card" href="cis_supply_chain/" markdown>
<h3>CIS Supply Chain</h3>
<p>CIS Software Supply Chain Security Guide. Source, build, dependency, and artifact controls.</p>
</a>

<a class="pg-doc-card" href="nist_ssdf/" markdown>
<h3>NIST SSDF</h3>
<p>Secure Software Development Framework — the federal SSDLC reference (SP 800-218).</p>
</a>

<a class="pg-doc-card" href="nist_800_53/" markdown>
<h3>NIST 800-53</h3>
<p>Federal control catalog (CI/CD subset). Maps findings to AC, AU, CM, IA, SI, SR families.</p>
</a>

<a class="pg-doc-card" href="nist_csf_2/" markdown>
<h3>NIST CSF 2.0</h3>
<p>Cybersecurity Framework — Govern, Identify, Protect, Detect, Respond, Recover.</p>
</a>

<a class="pg-doc-card" href="nist_800_190/" markdown>
<h3>NIST 800-190</h3>
<p>Application Container Security Guide — image, registry, runtime, host hardening.</p>
</a>

<a class="pg-doc-card" href="slsa/" markdown>
<h3>SLSA Build Track</h3>
<p>Supply-chain Levels for Software Artifacts. Provenance, hermeticity, signing posture.</p>
</a>

<a class="pg-doc-card" href="pci_dss_v4/" markdown>
<h3>PCI DSS v4.0</h3>
<p>Payment Card Industry Data Security Standard, CI/CD subset (logging, secret management, change control).</p>
</a>

<a class="pg-doc-card" href="esf_supply_chain/" markdown>
<h3>NSA/CISA ESF</h3>
<p>Enduring Security Framework — Securing the Software Supply Chain (developer, customer, supplier).</p>
</a>

<a class="pg-doc-card" href="openssf_scorecard/" markdown>
<h3>OpenSSF Scorecard</h3>
<p>Open-source project security health metrics. Pinned-deps, branch-protection, signing-keys, dangerous workflows.</p>
</a>

<a class="pg-doc-card" href="s2c2f/" markdown>
<h3>S2C2F</h3>
<p>Secure Supply Chain Consumption Framework — ingest, inventory, scan, rebuild, fix.</p>
</a>

<a class="pg-doc-card" href="soc2/" markdown>
<h3>SOC 2</h3>
<p>Trust Services Criteria. Audit-friendly mappings for Security, Confidentiality, and Availability.</p>
</a>

</div>

## Using standards at runtime

```bash
pipeline_check --list-standards                          # list registered standards
pipeline_check --pipeline aws --standard owasp_cicd_top_10  # filter to one
pipeline_check --pipeline aws --standard owasp_cicd_top_10 --standard nist_ssdf  # multiple
```

Omit `--standard` to include every registered standard.

## Architecture

A standard is pure data — no code. Each one is a Python module in
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
