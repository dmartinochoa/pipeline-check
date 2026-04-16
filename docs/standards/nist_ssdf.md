# NIST Secure Software Development Framework (SP 800-218 v1.1)

- **Version:** SP 800-218 v1.1
- **URL:** https://csrc.nist.gov/pubs/sp/800/218/final
- **Scope:** Tasks in the Prepare the Organization (PO), Protect the
  Software (PS), Produce Well-Secured Software (PW), and Respond to
  Vulnerabilities (RV) practice areas whose evidence can be collected
  from CI/CD configuration state.

## Tasks evidenced

| Task   | Title                                                                             |
|--------|-----------------------------------------------------------------------------------|
| PO.3.2 | Implement and maintain supporting toolchains with security controls               |
| PO.3.3 | Configure the toolchain to generate an audit trail of SDLC activities             |
| PO.5.1 | Separate and protect each environment involved in software development            |
| PS.1.1 | Store all forms of code based on least-privilege and tamper-resistance            |
| PS.2.1 | Make software integrity verification information available                        |
| PS.3.1 | Securely archive the necessary files and data for each software release           |
| PS.3.2 | Collect, safeguard, maintain, and share provenance data                           |
| PW.4.1 | Acquire and maintain well-secured 3rd-party software components                   |
| PW.4.4 | Verify that acquired components behave as expected                                |
| PW.9.1 | Configure software to have secure settings by default                             |
| RV.1.1 | Gather information about potential vulnerabilities in released software           |

## Not covered

Tasks requiring SCM policy introspection (PO.1 governance, PO.2
role assignment), human process (PW.7 code review), or incident response
telemetry (RV.2, RV.3) are out of scope for a CI/CD configuration scan.
