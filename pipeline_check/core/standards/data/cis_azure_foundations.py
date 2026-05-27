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
    },
)
