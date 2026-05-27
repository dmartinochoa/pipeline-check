"""CIS Microsoft Azure Foundations Benchmark v2.1.0, CI/CD-relevant subset.

Only the controls this scanner's checks can evidence are included.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_azure_foundations",
    title="CIS Microsoft Azure Foundations Benchmark",
    version="2.1.0",
    url="https://www.cisecurity.org/benchmark/azure",
    controls={
        # Identity and Access Management
        "1.21": "Ensure that no custom subscription administrator roles are created",
        "1.24": "Ensure that custom role permissions are managed and reviewed",
        # Entra ID (formerly Azure AD)
        "1.1.1": "Ensure Security Defaults are enabled on Azure Active Directory",
        "1.1.2": "Ensure that multi-factor authentication is enabled for all privileged users",
        # Storage Accounts
        "3.1": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "3.7": "Ensure default network access rule for storage accounts is set to deny",
        "3.10": "Ensure storage account access keys are periodically regenerated",
        "3.12": "Ensure storage for critical data is encrypted with Customer-Managed Key",
        # Logging and Monitoring
        "5.1.2": "Ensure Diagnostic Setting captures appropriate categories",
        "5.1.5": "Ensure that logging for Azure Key Vault is 'Enabled'",
        "5.2.1": "Ensure that Activity Log Alert exists for Create Policy Assignment",
        "5.2.2": "Ensure that Activity Log Alert exists for Delete Policy Assignment",
        "5.2.4": "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
        # Key Vault
        "8.1": "Ensure that the expiration date is set on all keys",
        "8.4": "Ensure the Key Vault is recoverable",
        "8.5": "Enable role-based access control for Azure Key Vault",
        # Container Registry
        "9.1": "Ensure Container Registry has admin user disabled",
        "9.2": "Ensure Container Registry has content trust enabled",
        # Networking
        "6.1": "Ensure that RDP access from the Internet is evaluated and restricted",
        "6.2": "Ensure that SSH access from the Internet is evaluated and restricted",
        "6.3": "Ensure no Network Security Group allows unrestricted ingress to port 3389",
        "6.5": "Ensure that Network Security Group flow log retention period is 'greater than 90 days'",
        "6.6": "Ensure that Network Watcher is 'Enabled'",
        # App Service
        "9.3": "Ensure that 'Web App Redirects All HTTP traffic to HTTPS' is set",
        "9.4": "Ensure Web App is using the latest version of TLS encryption",
        "9.5": "Ensure that Register with Azure AD is enabled on App Service",
        "9.10": "Ensure FTP deployments are Disabled",
        "9.11": "Ensure Azure Key Vaults are used to store secrets",
        # SQL Database
        "4.1.1": "Ensure that 'Auditing' is set to 'On'",
        "4.1.3": "Ensure that 'Data encryption' is set to 'On' for SQL databases",
        "4.1.4": "Ensure that 'Azure Active Directory Admin' is configured for SQL Servers",
        "4.2.1": "Ensure that Advanced Threat Protection (ATP) on a SQL Server is set to 'On'",
        # Virtual Machines
        "7.1": "Ensure Virtual Machines use Managed Disks",
        "7.2": "Ensure that OS and Data disks are encrypted with CMK",
        "7.4": "Ensure that only approved extensions are installed",
    },
    mappings={
        # Entra ID / Identity
        "ENTRA-001": ["1.21", "1.24"],
        "ENTRA-002": ["1.1.2"],
        "ENTRA-003": ["1.1.1"],
        # Storage
        "AZST-001": ["3.7"],
        "AZST-002": ["3.1"],
        "AZST-003": ["3.12"],
        # Key Vault
        "AKV-001": ["8.4"],
        "AKV-002": ["8.4"],
        "AKV-003": ["8.5"],
        # Container Registry
        "ACR-001": ["9.1"],
        "ACR-002": ["9.1"],
        "ACR-003": ["9.2"],
        # Logging and Monitoring
        "AZMON-001": ["5.1.2"],
        "AZMON-002": ["5.1.2", "5.1.5"],
        "AZMON-003": ["5.2.1", "5.2.2", "5.2.4"],
        # ── Phase-2 Azure rules ──────────────────────────────────────
        "ENTRA-004": ["1.1.2"],                            # cond access MFA
        "ENTRA-005": ["1.24"],                             # ext user restrict
        "ENTRA-006": ["1.1.1"],                            # risky signin
        "AZST-004":  ["3.1"],                              # min TLS
        "AZST-005":  ["3.10"],                             # lifecycle
        "AZST-006":  ["3.10"],                             # key rotation
        "AKV-004":   ["8.1"],                              # key expiry
        "AKV-005":   ["8.1"],                              # secret expiry
        "AKV-006":   ["8.5"],                              # RBAC
        "ACR-004":   ["9.1"],                              # defender scan
        "ACR-005":   ["9.2"],                              # tag immutability
        "AZMON-004": ["5.1.5"],                            # KV diagnostics
        "AZMON-005": ["6.5"],                              # NSG flow retention
        "AZMON-006": ["5.1.2"],                            # LAW retention
        "AZMON-007": ["5.2.1"],                            # svc health alert
        "AZNW-001":  ["6.1", "6.2", "6.3"],               # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["6.5", "6.6"],                       # flow logs
        "AZNW-003":  ["6.6"],                              # WAF
        "AZNW-004":  ["6.3"],                              # deny-all
        "AZNW-005":  ["6.6"],                              # public IP VM
        "AZAPP-001": ["9.3"],                              # HTTPS
        "AZAPP-002": ["9.4"],                              # TLS
        "AZAPP-003": ["9.5"],                              # managed identity
        "AZAPP-004": ["9.11"],                             # remote debug
        "AZAPP-005": ["9.10"],                             # FTP
        "AZSQL-001": ["4.1.3"],                            # TDE CMK
        "AZSQL-002": ["4.1.1"],                            # auditing
        "AZSQL-003": ["6.3"],                              # public access
        "AZSQL-004": ["4.1.4"],                            # AAD admin
        "AZSQL-005": ["4.2.1"],                            # threat detect
        "AZVM-001":  ["7.2"],                              # disk encrypt
        "AZVM-002":  ["6.6"],                              # public IP
        "AZVM-003":  ["6.6"],                              # JIT
        "AZVM-004":  ["7.4"],                              # OS patch
        "AZVM-005":  ["7.1"],                              # managed identity
    },
)
