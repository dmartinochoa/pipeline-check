"""GCB-018. Legacy KMS-encrypted ``secrets:`` block instead of Secret Manager."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-018",
    title="Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Migrate from the top-level ``secrets:`` block (KMS-encrypted "
        "values stored inline in the YAML) to ``availableSecrets`` + "
        "Secret Manager. Replace each ``secrets[].secretEnv`` mapping "
        "with a ``versionName`` reference under "
        "``availableSecrets.secretManager``. Secret Manager rotates "
        "without re-encrypting and re-committing the YAML, scopes "
        "access via IAM rather than the KMS key's IAM, and produces "
        "an explicit audit log entry on every read."
    ),
    docs_note=(
        "Cloud Build supports two secret-injection mechanisms. The "
        "older ``secrets:`` block carries KMS-encrypted ciphertext "
        "directly in the YAML; the cipher is decrypted at build time "
        "if the build's service account has ``cloudkms.cryptoKey"
        "Decrypter`` on the key. The newer ``availableSecrets`` "
        "block references Secret Manager versions by URL, which is "
        "the documented modern approach. The legacy form still "
        "works, but rotating a value means re-encrypting and "
        "committing a new ciphertext."
    ),
    known_fp=(
        "Builds that use both forms during a migration trip the "
        "rule on the legacy block. That's intentional, finishing "
        "the migration is the fix.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    legacy = doc.get("secrets")
    if not (isinstance(legacy, list) and legacy):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No legacy ``secrets:`` block declared.",
            recommendation=RULE.recommendation, passed=True,
        )
    # ``legacy`` is now narrowed to a non-empty list. Pull out the
    # KMS key names for the description.
    entries: list[str] = []
    for s in legacy:
        if isinstance(s, dict):
            kms_key = s.get("kmsKeyName")
            if isinstance(kms_key, str):
                entries.append(kms_key)
    desc = (
        f"Legacy KMS-encrypted ``secrets:`` block declares "
        f"{len(legacy)} entr"
        f"{'y' if len(legacy) == 1 else 'ies'}"
        + (f" (kmsKeyName(s): {', '.join(entries[:3])}{'…' if len(entries) > 3 else ''})" if entries else "")
        + ". Migrate to ``availableSecrets`` + Secret Manager."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
