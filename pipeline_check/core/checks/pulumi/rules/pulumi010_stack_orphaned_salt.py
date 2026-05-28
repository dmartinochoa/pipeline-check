"""PULUMI-010. Pulumi stack carries both encryptionsalt and a cloud-KMS provider."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-010",
    title="Pulumi stack carries both encryptionsalt and a cloud-KMS provider",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-323",),
    recommendation=(
        "Remove the stale ``encryptionsalt`` line from "
        "``Pulumi.<stack>.yaml`` once every secret value has "
        "been re-encrypted under the new cloud-KMS provider. "
        "The migration sequence is:\n\n"
        "1. ``pulumi stack change-secrets-provider "
        "\"<kms-url>\"``. Pulumi rotates every "
        "``secure:`` entry through the new provider and writes "
        "the wrapped DEK to ``encryptedkey:``.\n"
        "2. Manually drop the ``encryptionsalt`` line from the "
        "stack file — Pulumi keeps it during the migration as "
        "a safety net but doesn't auto-delete.\n\n"
        "Without the cleanup, the stack file documents two "
        "incompatible encryption posts (passphrase-derived "
        "salt + KMS-managed DEK), which:\n\n"
        "* Confuses operator audit (which posture is in "
        "force?).\n"
        "* Leaves the salt in git history, which is the only "
        "secret-bearing artifact a future attacker would need "
        "if the operator ever reverts to the passphrase "
        "provider for a single secret.\n"
        "* Trips static-analysis tools (this one included) that "
        "read the salt's presence as evidence of passphrase "
        "encryption even when the salt is no longer the active "
        "encryption mechanism."
    ),
    docs_note=(
        "Reads ``Pulumi.<stack>.yaml`` and fires when both "
        "``encryptionsalt:`` and ``secretsprovider:`` are set "
        "AND the provider URL is a cloud-KMS scheme "
        "(``awskms://`` / ``azurekeyvault://`` / ``gcpkms://`` / "
        "``hashivault://``). The shape signals a post-migration "
        "stack file where the operator switched to cloud KMS "
        "but didn't drop the old passphrase salt.\n\n"
        "Distinct from PULUMI-001 (passphrase secretsprovider — "
        "active passphrase encryption). This rule catches the "
        "cleanup-debt case where KMS is active but evidence of "
        "the old passphrase posture lingers."
    ),
    known_fp=(
        "Operators who deliberately want to maintain the "
        "passphrase-recovery option as a safety net trip this "
        "rule by design. The right migration discipline is to "
        "drop the salt; suppress per file if the operational "
        "policy genuinely requires the dual-encryption-recovery "
        "fallback.",
    ),
    incident_refs=(
        "Pattern in Pulumi-using teams that migrate from "
        "passphrase to cloud KMS for secrets management: the "
        "stack file's ``encryptionsalt`` line is left "
        "in place for 'safety' or 'in case we need to roll "
        "back', the migration documentation never reaches the "
        "cleanup step. The lingering salt becomes the "
        "compromise-of-last-resort path if the cloud KMS "
        "provider is ever bypassed.",
    ),
    exploit_example=(
        "# Vulnerable: stack file has both salt and KMS.\n"
        "# Pulumi.prod.yaml\n"
        "secretsprovider: awskms://alias/pulumi-prod?region=us-east-1\n"
        "encryptedkey: v1:wrapped-DEK\n"
        "encryptionsalt: v1:abc:def:gh   ← stale, should be removed\n"
        "config:\n"
        "  myapp:dbPassword:\n"
        "    secure: v1:encrypted-with-the-DEK\n"
        "\n"
        "# Risk: operator audit can't tell at a glance which\n"
        "# posture is in force. The salt's presence suggests\n"
        "# passphrase encryption is still recoverable; if a\n"
        "# previous passphrase was ever leaked, every secret\n"
        "# value still encrypted under it (in git history)\n"
        "# remains compromised regardless of the current KMS\n"
        "# posture.\n"
        "\n"
        "# Safe: drop the salt.\n"
        "# Pulumi.prod.yaml\n"
        "secretsprovider: awskms://alias/pulumi-prod?region=us-east-1\n"
        "encryptedkey: v1:wrapped-DEK\n"
        "config:\n"
        "  myapp:dbPassword:\n"
        "    secure: v1:encrypted-with-the-DEK\n"
    ),
)


_KMS_PREFIXES: tuple[str, ...] = (
    "awskms://",
    "azurekeyvault://",
    "gcpkms://",
    "hashivault://",
)


def check(ctx: PulumiContext) -> Finding:
    if not ctx.stacks:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=(
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            ),
            description=(
                "No Pulumi.<stack>.yaml files; nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for stack in ctx.stacks:
        if not stack.encryption_salt:
            continue
        provider = stack.secrets_provider or ""
        if not any(provider.startswith(p) for p in _KMS_PREFIXES):
            continue
        offenders.append(
            f"{stack.stack_name} ({stack.path})"
        )
        line_no = 1
        if "encryptionsalt" in stack.text:
            line_no = (
                stack.text[:stack.text.index("encryptionsalt")].count("\n")
                + 1
            )
        locations.append(Location(
            path=stack.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No stack file carries both encryptionsalt and a cloud-"
        "KMS secretsprovider."
        if passed else
        f"{len(offenders)} stack file(s) carry both an "
        f"encryptionsalt and a cloud-KMS secretsprovider: "
        f"{', '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. The salt is "
        f"cleanup debt from a passphrase->KMS migration that "
        f"didn't finish."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            ctx.stacks[0].path if offenders else
            (ctx.projects[0].path if ctx.projects else "Pulumi.yaml")
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
