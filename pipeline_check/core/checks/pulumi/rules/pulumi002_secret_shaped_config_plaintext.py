"""PULUMI-002. Stack config carries a secret-shaped key in plaintext."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    PulumiContext,
    is_secret_shaped_key,
    is_secret_value,
)

RULE = Rule(
    id="PULUMI-002",
    title="Pulumi stack config carries a secret-shaped key in plaintext",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-256", "CWE-312"),
    recommendation=(
        "Convert every plaintext entry whose key looks like a "
        "credential into a Pulumi secret. Run ``pulumi config set "
        "--secret <project>:<key> <value>`` on each stack and the "
        "CLI re-encrypts the value through the configured "
        "secretsprovider (see PULUMI-001) and rewrites the stack "
        "file's ``config:`` entry from ``<key>: <plaintext>`` to "
        "``<key>: { secure: <ciphertext> }``. Plaintext entries in "
        "the stack file land in git, so anyone with repo read "
        "access (or an old clone) can recover the credential "
        "indefinitely."
    ),
    docs_note=(
        "Walks every ``Pulumi.<stack>.yaml`` ``config:`` block "
        "and fires on entries whose key matches a curated "
        "secret-shape list (``password`` / ``token`` / "
        "``secret`` / ``apikey`` / ``private_key`` / ``credential`` "
        "/ ``access_key`` / ``client_secret``) and whose value is "
        "not wrapped in ``{secure: ...}``. Wrapped entries "
        "(``{\"secure\": \"v1:...\"}``) pass — the value is "
        "already encrypted with the stack's secretsprovider.\n\n"
        "Match is case-insensitive substring on the key (so "
        "``MyApp:DbPassword`` and ``myapp:dbpassword`` both fire). "
        "Project-prefixed keys (``my-project:apiToken``) are "
        "matched on the full key string, so a value's namespace "
        "is included in the surface."
    ),
    known_fp=(
        "Some non-credential settings happen to contain the word "
        "``key`` (``cache_key_prefix``, ``primary_key``, "
        "``key_name``). The rule's substring matcher will trip on "
        "those; suppress per entry with a one-line rationale "
        "naming the legitimate identifier-as-key usage. Where "
        "possible, rename the config key to avoid the false "
        "match.",
    ),
    incident_refs=(
        "Pattern of plaintext stack-config secrets surfacing in "
        "open-source Pulumi project audits: a ``demo`` stack "
        "shipped with literal ``dbPassword: changeme123`` was "
        "promoted to production by a contributor who didn't "
        "realize the ``demo`` value was load-bearing. The "
        "passphrase-shaped key escaped review because the value "
        "looked obviously fake.",
    ),
    exploit_example=(
        "# Vulnerable: secret-shaped key with plaintext value.\n"
        "# Pulumi.prod.yaml\n"
        "config:\n"
        "  myapp:dbPassword: hunter2-but-with-extra-chars-1234567890\n"
        "  myapp:apiToken: ghp_abc...long-real-looking-token\n"
        "  myapp:clientSecret: rotating-secret-please-handle-with-care\n"
        "\n"
        "# Attack: every push to the repo's main branch lands\n"
        "# the file in git history. Any clone (CI cache,\n"
        "# contractor laptop, archived backup) carries the\n"
        "# credentials in plaintext indefinitely. Rotation\n"
        "# requires updating every consumer + scrubbing git\n"
        "# history, which is operationally rarely done.\n"
        "\n"
        "# Safe: wrap each entry as a secret.\n"
        "# $ pulumi config set --secret myapp:dbPassword <value>\n"
        "# Pulumi.prod.yaml\n"
        "config:\n"
        "  myapp:dbPassword:\n"
        "    secure: v1:abc...:cipher-text\n"
        "  myapp:apiToken:\n"
        "    secure: v1:abc...:cipher-text\n"
        "\n"
        "# Now the plaintext value never lands in git; only the\n"
        "# ciphertext under the configured secretsprovider does."
    ),
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
        for key, value in stack.config.items():
            if not isinstance(key, str):
                continue
            if not is_secret_shaped_key(key):
                continue
            if is_secret_value(value):
                continue
            offenders.append(f"{stack.stack_name}:{key}")
            # Best-effort line number: search for the literal key.
            try:
                line_no = (
                    stack.text[:stack.text.index(key)].count("\n") + 1
                )
            except ValueError:
                line_no = 1
            locations.append(Location(
                path=stack.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "Every secret-shaped config key is wrapped in a "
        "``secure:`` value."
        if passed else
        f"{len(offenders)} secret-shaped config key(s) carry "
        f"plaintext values: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each value lands "
        f"in git history; rotation requires consumer updates plus "
        f"history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            ctx.stacks[0].path if not offenders
            else next(
                s.path for s in ctx.stacks
                if any(o.startswith(f"{s.stack_name}:") for o in offenders)
            )
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
