"""SCM-025. Repo has write-enabled deploy keys."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-025",
    title="Repo has write-enabled deploy keys (push backdoor)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-269"),
    recommendation=(
        "Convert every deploy key to read-only (Settings → Deploy "
        "keys → uncheck ``Allow write access``), then rotate the "
        "underlying SSH key pair if the previous holder no longer "
        "needs write access. Deploy keys are repo-scoped SSH "
        "credentials that bypass GitHub's normal RBAC — anyone "
        "with the private half can push directly, side-stepping "
        "branch protection (SCM-001), required reviews (SCM-002), "
        "CODEOWNERS (SCM-011), and the user-account audit trail. "
        "If the use case genuinely needs push (a CI runner that "
        "tags releases, a release-bot account), prefer a "
        "fine-grained PAT or a GitHub App with constrained scope, "
        "both of which carry user-visible audit-log entries that "
        "deploy keys do not."
    ),
    docs_note=(
        "Reads ``GET /repos/{owner}/{repo}/keys`` and flags every "
        "deploy key whose ``read_only`` field is false. Requires "
        "``admin`` scope on the repo; without it GitHub returns "
        "403 / 404 and the rule passes silently with an "
        "unavailability note. Deploy keys come in two shapes: "
        "read-only (clone access only, safe equivalent of a "
        "public-fork checkout) and write-enabled (push access, "
        "the failure case this rule catches). The endpoint "
        "returns the SSH public key plus metadata, never the "
        "private half — the scan can't recover the credential, "
        "only enumerate which keys exist and what scope each "
        "carries.\n\n"
        "Complements every branch-protection rule in the pack: "
        "without SCM-025, an unaudited write deploy key bypasses "
        "the entire control set the other rules document. Also "
        "pairs with SCM-018 (PR-review bypass allowance) and "
        "SCM-019 (push-restriction allowlist), which catch the "
        "same risk shape on the user / team side."
    ),
    known_fp=(
        "Some CI flows legitimately use a write deploy key for "
        "release tagging or auto-generated docs commits. The "
        "right pattern is a GitHub App or a fine-grained PAT with "
        "an audit trail; deploy keys persist indefinitely and "
        "leave no record of who used them. Suppress with a "
        "one-line rationale that names the specific key title.",
    ),
    incident_refs=(
        "Long-running pattern of forgotten deploy keys retaining "
        "write access years after the original owner left an org. "
        "Public catalogs of leaked SSH private keys on paste sites "
        "and GitHub itself routinely hit configured deploy keys; "
        "the corresponding repo is push-compromised until the "
        "operator revokes the key.",
    ),
    exploit_example=(
        "# Vulnerable: a write-enabled deploy key sits on the repo\n"
        "# for years. The private half lived on a contractor's\n"
        "# laptop and was checked into a public gist during a\n"
        "# transient debug session.\n"
        "GET /repos/acme/payments-api/keys\n"
        "[\n"
        "  {\n"
        "    \"id\": 42,\n"
        "    \"title\": \"ci-runner-prod (added 2021-03)\",\n"
        "    \"key\": \"ssh-ed25519 AAAA... ci-runner\",\n"
        "    \"read_only\": false,\n"
        "    \"created_at\": \"2021-03-04T10:00:00Z\"\n"
        "  }\n"
        "]\n"
        "\n"
        "# Attack: ``git push git@github.com:acme/payments-api.git``\n"
        "# using the leaked private key writes directly to master,\n"
        "# bypassing every required-review / CODEOWNERS / status-\n"
        "# check gate the other SCM rules document. The push shows\n"
        "# up in the audit log as ``key:42`` rather than a user\n"
        "# account, so detection requires correlation across\n"
        "# audit-log events most operators never review.\n"
        "\n"
        "# Safe: revoke the deploy key. If write access is\n"
        "# genuinely required for CI tagging, switch to a GitHub\n"
        "# App with constrained scope plus a one-line audit-log\n"
        "# entry per push."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; deploy-keys check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    keys = snapshot.deploy_keys
    if keys is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/keys endpoint unavailable (token likely "
                "lacks ``admin`` scope on the repo)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not keys:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="No deploy keys configured.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for key in keys:
        if key.get("read_only") is True:
            continue
        title = key.get("title")
        key_id = key.get("id")
        if isinstance(title, str) and title:
            offenders.append(title)
        elif isinstance(key_id, int):
            offenders.append(f"key:{key_id}")
        else:
            offenders.append("(unnamed key)")
    passed = not offenders
    desc = (
        f"All {len(keys)} deploy key(s) are read-only."
        if passed else
        f"{len(offenders)} write-enabled deploy key(s) configured: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anyone with the "
        f"private half pushes directly to the repo, bypassing "
        f"branch protection and the user-account audit trail."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
