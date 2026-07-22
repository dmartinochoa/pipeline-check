"""PULUMI-001. Stack uses passphrase-based secret encryption.

The default Pulumi posture for secret encryption is a passphrase
the user enters at every CLI invocation (``PULUMI_CONFIG_PASSPHRASE``
or interactive prompt). The passphrase doubles as the only thing
gating the encrypted ``secure:`` config values from being read; if
it leaks into a shell history, CI env-var dump, ticketing thread,
or screenshot, every stack secret encrypted under it is exposed.
Cloud-managed KMS providers (``awskms://`` / ``azurekeyvault://`` /
``gcpkms://`` / ``hashivault://``) move the key into a managed key
vault with rotation + audit + per-decrypt logging, which is the
posture the rule enforces.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext, PulumiStack

RULE = Rule(
    id="PULUMI-001",
    title="Pulumi stack uses passphrase-based secret encryption",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-321", "CWE-798"),
    recommendation=(
        "Switch every stack to a cloud-managed KMS secrets provider. "
        "Run ``pulumi stack change-secrets-provider \"<url>\"`` on "
        "each stack with one of:\n\n"
        "* ``awskms://<key-id>?region=<region>``\n"
        "* ``azurekeyvault://<vault-name>.vault.azure.net/<key>/<version>``\n"
        "* ``gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>``\n"
        "* ``hashivault://<key-name>``\n\n"
        "Each KMS-backed provider keeps the actual encryption key in "
        "a managed vault: rotation, per-decrypt audit logs, and IAM-"
        "gated access are all properties of the vault, not the "
        "Pulumi project. The passphrase posture leaks the entire "
        "secret table to anyone who recovers the passphrase, no "
        "matter how strong it is. After the switch, ``encryptionsalt`` "
        "in ``Pulumi.<stack>.yaml`` is replaced by ``encryptedkey`` "
        "(the wrapped KMS-encrypted DEK) and the stack secrets "
        "transition into KMS-managed encryption."
    ),
    docs_note=(
        "Reads ``Pulumi.<stack>.yaml`` and fires for a "
        "passphrase-backed stack: either ``secretsprovider`` is "
        "``passphrase``, or ``secretsprovider`` is absent but an "
        "``encryptionsalt`` is present (Pulumi writes the salt only "
        "for passphrase-backed stacks). A stack with neither a "
        "provider nor a salt has no encrypted secrets to protect, so "
        "it doesn't fire. Cloud-KMS providers store an "
        "``encryptedkey`` field instead; either signal is enough "
        "to pass the rule.\n\n"
        "Skipped when the project has no stack files (no stack "
        "yet initialized); the rule has nothing to evaluate in "
        "that case. The default Pulumi-service backend "
        "(``app.pulumi.com``) is a separate concern, the hosted "
        "service stores stack state encrypted at rest in its own "
        "envelope but the ``secretsprovider`` field still governs "
        "*how* the per-stack secrets are encrypted before upload."
    ),
    known_fp=(
        "Solo / hobby projects that deliberately use the "
        "passphrase posture for portability (no cloud account, no "
        "team) trip this rule by design. Suppress per stack with a "
        "one-line rationale naming the project's single-author "
        "posture. Teams shipping to production should not suppress.",
    ),
    incident_refs=(
        "Long-running pattern of CI logs / shell histories leaking "
        "``PULUMI_CONFIG_PASSPHRASE`` into team chat, Sentry events, "
        "or ticketing systems. The passphrase doubles as the only "
        "gate on the stack's secret table; recovery of one leaked "
        "value compromises every secret encrypted under it "
        "(database URLs, API tokens, OIDC client secrets) "
        "indistinguishably from a key-rotation event.",
    ),
    exploit_example=(
        "# Vulnerable: passphrase-based encryption.\n"
        "# Pulumi.prod.yaml\n"
        "encryptionsalt: v1:abc123:RNG-output:cipher-text\n"
        "config:\n"
        "  myapp:dbPassword:\n"
        "    secure: v1:encrypted-with-the-passphrase\n"
        "\n"
        "# Attack: a CI step that runs ``pulumi up`` with\n"
        "# ``PULUMI_CONFIG_PASSPHRASE`` set in the runner env. A\n"
        "# job that crashes mid-deploy and dumps env vars into\n"
        "# Sentry leaks the passphrase. Anyone who can read the\n"
        "# crash report decrypts every secure: entry in every\n"
        "# stack file (every Pulumi.<stack>.yaml committed to\n"
        "# the repo).\n"
        "\n"
        "# Safe: cloud-managed KMS provider.\n"
        "# Pulumi.prod.yaml\n"
        "secretsprovider: awskms://alias/pulumi-prod?region=us-east-1\n"
        "encryptedkey: <wrapped-DEK>\n"
        "config:\n"
        "  myapp:dbPassword:\n"
        "    secure: v1:encrypted-with-the-DEK\n"
        "\n"
        "# Now decrypting requires kms:Decrypt on the KMS alias,\n"
        "# which is audited, IAM-gated, and revocable independently\n"
        "# of the Pulumi project itself."
    ),
)


def _is_kms_provider(provider: str) -> bool:
    """Return ``True`` when ``provider`` URL scheme is one of the
    cloud-managed KMS schemes Pulumi supports."""
    return any(
        provider.startswith(prefix)
        for prefix in (
            "awskms://",
            "azurekeyvault://",
            "gcpkms://",
            "hashivault://",
        )
    )


def _stack_is_passphrase(stack: PulumiStack) -> bool:
    """A stack uses passphrase encryption when ``secretsprovider`` is
    absent or explicitly set to ``passphrase``. ``encryptionsalt``
    presence is a confirming signal but not strictly required (a
    misconfigured stack that has the salt but no provider is still
    passphrase-encrypted at decryption time)."""
    if stack.secrets_provider == "passphrase":
        return True
    if stack.secrets_provider is None and stack.encryption_salt:
        # Salt without an explicit provider = passphrase default.
        return True
    if (
        stack.secrets_provider is not None
        and not _is_kms_provider(stack.secrets_provider)
    ):
        # Other unknown scheme (``"local://..."`` etc.); flag as
        # not-KMS until proven otherwise.
        return True
    return False


def check(ctx: PulumiContext) -> Finding:
    if not ctx.stacks:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=(
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            ),
            description=(
                "No Pulumi.<stack>.yaml files in the project; no "
                "stack-encryption posture to evaluate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for stack in ctx.stacks:
        if _stack_is_passphrase(stack):
            offenders.append(
                f"{stack.stack_name} ({stack.path})"
            )
            locations.append(Location(
                path=stack.path, start_line=1, end_line=1,
            ))
    passed = not offenders
    desc = (
        "Every Pulumi stack uses a cloud-managed KMS secrets "
        "provider."
        if passed else
        f"{len(offenders)} stack(s) use passphrase-based "
        f"encryption (no cloud-KMS secretsprovider): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A leaked "
        f"passphrase decrypts every secure: entry in every "
        f"committed stack file."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=offenders[0].split(" ", 1)[1].strip("()") if offenders
        else (ctx.projects[0].path if ctx.projects else "Pulumi.yaml"),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
