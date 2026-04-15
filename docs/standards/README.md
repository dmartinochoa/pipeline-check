# Compliance standards

Every finding produced by the scanner carries a list of `ControlRef` objects
— references to controls in registered compliance standards. The same check
can evidence controls in multiple standards at once.

## Registered standards

| Name                   | Title                                      | Version | Docs                                |
|------------------------|--------------------------------------------|---------|-------------------------------------|
| `owasp_cicd_top_10`    | OWASP Top 10 CI/CD Security Risks          | 2022    | [owasp_cicd_top_10.md](owasp_cicd_top_10.md) |
| `cis_aws_foundations`  | CIS AWS Foundations Benchmark (subset)     | 3.0.0   | [cis_aws_foundations.md](cis_aws_foundations.md) |
| `cis_supply_chain`     | CIS Software Supply Chain Security Guide   | 1.0     | [cis_supply_chain.md](cis_supply_chain.md) |
| `nist_ssdf`            | NIST Secure Software Development Framework | SP 800-218 v1.1 | [nist_ssdf.md](nist_ssdf.md) |
| `nist_800_53`          | NIST SP 800-53 Rev. 5 (CI/CD subset)       | Rev. 5  | [nist_800_53.md](nist_800_53.md) |
| `slsa`                 | SLSA Build Track                           | 1.0     | [slsa.md](slsa.md) |
| `pci_dss_v4`           | PCI DSS v4.0 (CI/CD subset)                | 4.0     | [pci_dss_v4.md](pci_dss_v4.md) |

List them at runtime with:

```bash
pipeline_check --list-standards
```

## Filtering by standard

To annotate findings with controls from a single standard only:

```bash
pipeline_check --pipeline aws --standard owasp_cicd_top_10
```

Repeat `--standard` to select multiple. Omit it to include every registered
standard.

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
- **Easy to extend:** adding SOC 2, NIST 800-53, or a bespoke internal
  policy is one new Python module.
