# Compliance standards

Every finding produced by the scanner carries a list of `ControlRef` objects
— references to controls in registered compliance standards. The same check
can evidence controls in multiple standards at once.

<div class="pg-doc-cards" markdown>

<a class="pg-doc-card" href="owasp_cicd_top_10/" markdown>
<span class="pg-doc-card__tag pg-doc-card__tag--accent">flagship</span>
<h3>OWASP Top 10 CI/CD</h3>
<p>The reference framework for CI/CD security risks. <strong>Full 10/10 coverage</strong> across providers.</p>
<span class="pg-doc-card__meta">2022 · <code>owasp_cicd_top_10</code></span>
</a>

<a class="pg-doc-card" href="cis_aws_foundations/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>CIS AWS Foundations</h3>
<p>CI/CD-relevant subset of the CIS AWS benchmark — IAM, S3, CloudTrail, KMS hardening.</p>
<span class="pg-doc-card__meta">3.0.0 · <code>cis_aws_foundations</code></span>
</a>

<a class="pg-doc-card" href="cis_supply_chain/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>CIS Supply Chain</h3>
<p>CIS Software Supply Chain Security Guide. Covers source, build, dependency, and artifact controls.</p>
<span class="pg-doc-card__meta">1.0 · <code>cis_supply_chain</code></span>
</a>

<a class="pg-doc-card" href="nist_ssdf/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>NIST SSDF</h3>
<p>Secure Software Development Framework. SP 800-218 v1.1 — the federal SSDLC reference.</p>
<span class="pg-doc-card__meta">800-218 v1.1 · <code>nist_ssdf</code></span>
</a>

<a class="pg-doc-card" href="nist_800_53/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>NIST 800-53</h3>
<p>Federal control catalog (CI/CD subset). Maps findings to AC, AU, CM, IA, SI, SR families.</p>
<span class="pg-doc-card__meta">Rev. 5 · <code>nist_800_53</code></span>
</a>

<a class="pg-doc-card" href="nist_csf_2/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>NIST CSF 2.0</h3>
<p>Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover.</p>
<span class="pg-doc-card__meta">2.0 · <code>nist_csf_2</code></span>
</a>

<a class="pg-doc-card" href="nist_800_190/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>NIST 800-190</h3>
<p>Application Container Security Guide — image, registry, runtime, host hardening.</p>
<span class="pg-doc-card__meta">2017 · <code>nist_800_190</code></span>
</a>

<a class="pg-doc-card" href="slsa/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>SLSA Build Track</h3>
<p>Supply-chain Levels for Software Artifacts. Provenance, hermeticity, signing posture.</p>
<span class="pg-doc-card__meta">1.0 · <code>slsa</code></span>
</a>

<a class="pg-doc-card" href="pci_dss_v4/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>PCI DSS v4.0</h3>
<p>Payment Card Industry Data Security Standard, CI/CD subset (logging, secret management, change control).</p>
<span class="pg-doc-card__meta">4.0 · <code>pci_dss_v4</code></span>
</a>

<a class="pg-doc-card" href="esf_supply_chain/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>NSA/CISA ESF</h3>
<p>Enduring Security Framework guidance — Securing the Software Supply Chain (developer + customer + supplier).</p>
<span class="pg-doc-card__meta">2022 · <code>esf_supply_chain</code></span>
</a>

<a class="pg-doc-card" href="openssf_scorecard/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>OpenSSF Scorecard</h3>
<p>Open-source project security health metrics. Pinned-deps, branch-protection, signing-keys, dangerous workflows.</p>
<span class="pg-doc-card__meta">5 · <code>openssf_scorecard</code></span>
</a>

<a class="pg-doc-card" href="s2c2f/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>S2C2F</h3>
<p>Secure Supply Chain Consumption Framework — ingest, inventory, scan, rebuild, fix.</p>
<span class="pg-doc-card__meta">2024-05 · <code>s2c2f</code></span>
</a>

<a class="pg-doc-card" href="soc2/" markdown>
<span class="pg-doc-card__tag">stable</span>
<h3>SOC 2</h3>
<p>Trust Services Criteria. Audit-friendly mappings for the Security, Confidentiality, and Availability trust principles.</p>
<span class="pg-doc-card__meta">2017 (rev. 2022) · <code>soc2</code></span>
</a>

</div>

## Using standards at runtime

List them:

```bash
pipeline_check --list-standards
```

Filter to one or several:

```bash
pipeline_check --pipeline aws --standard owasp_cicd_top_10
pipeline_check --pipeline aws --standard owasp_cicd_top_10 --standard nist_ssdf
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
