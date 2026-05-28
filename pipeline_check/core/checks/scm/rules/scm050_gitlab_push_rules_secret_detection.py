"""SCM-050. GitLab push rules do not block secret-shaped commits."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    gitlab_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-050",
    title="GitLab push rules do not block secret-shaped commits",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-538"),
    recommendation=(
        "On the project Settings -> Repository -> Push Rules panel, "
        "enable ``Prevent committing secrets to Git``. The setting "
        "maps to the API field ``prevent_secrets: true`` on "
        "``PUT /projects/:id/push_rule`` and rejects any commit whose "
        "added lines match GitLab's bundled secret-pattern catalog "
        "(``aws_secret_key``, ``gcp_credentials.json``, ``id_rsa``, "
        "``id_dsa``, ``server.crt``, ``database.yml`` with literal "
        "credentials). Pair with ``file_name_regex`` to block "
        "credential-shaped filenames (``\\.env$``, ``\\.npmrc$``, "
        "``\\.pypirc$``). Without ``prevent_secrets``, the platform "
        "accepts a commit that adds ``AKIA[A-Z0-9]{16}`` literals "
        "into the repo, leaving cleanup to retroactive secret-"
        "scanning + revocation. The push-rule guard is the "
        "shift-left equivalent: server-side rejection at "
        "``git push`` time, before the bad commit ever lands."
    ),
    docs_note=(
        "Reads ``repo_meta._gitlab_push_rule.prevent_secrets`` "
        "(populated from ``GET /projects/:id/push_rule``) and "
        "fires when the field is False or missing. The push-rule "
        "endpoint requires GitLab Premium / Ultimate; on Free the "
        "endpoint returns ``404`` and the rule passes silently "
        "with an unavailability note (the operator sees the "
        "deliberate skip rather than a silent absence). The same "
        "endpoint also surfaces ``commit_committer_check`` "
        "(SCM-051) and ``reject_unsigned_commits`` (already "
        "consumed by SCM-006), so the fetcher only issues one "
        "request to populate the whole push-rule slot."
    ),
    known_fp=(
        "GitLab Self-Managed deployments running CE (community "
        "edition, no Premium license) don't expose push rules at "
        "all; this rule passes silently on those snapshots. "
        "Suppress per-repo for known-CE installations to avoid "
        "the cosmetic skip note polluting the report.",
    ),
    incident_refs=(
        "Long-running pattern of AWS / GCP credentials accidentally "
        "committed to GitLab repos and only caught by retroactive "
        "secret-scanning hours / days later; the GitHub equivalent "
        "(secret scanning + push protection, SCM-015) blocks the "
        "same class of commit at push time. Public examples: "
        "https://about.gitlab.com/blog/2023/04/20/gitlab-secret-detection/",
    ),
    exploit_example=(
        "# Vulnerable: GitLab push rules don't block secret-shaped\n"
        "# commits. A maintainer pastes an AWS access key into a\n"
        "# debug script and pushes; GitLab accepts the commit and\n"
        "# the credential is now in repo history. Retroactive\n"
        "# scanning may flag it minutes later, but by then the\n"
        "# secret is replicated to every clone and CI cache.\n"
        "GET /projects/group%2Fproject/push_rule\n"
        "{\n"
        "  \"id\": 1,\n"
        "  \"prevent_secrets\": false,\n"
        "  \"reject_unsigned_commits\": false,\n"
        "  \"commit_committer_check\": false\n"
        "}\n"
        "\n"
        "# Attack: a contributor with push access commits\n"
        "# ``aws_access_key_id = AKIA...`` to a tooling script.\n"
        "# Push succeeds. The credential is now public-ish (any\n"
        "# clone has it) until rotation; revocation doesn't undo\n"
        "# what was already scraped from the repo.\n"
        "\n"
        "# Safe: enable ``prevent_secrets`` on the project. The\n"
        "# push is rejected with a server-side message naming the\n"
        "# matched pattern; the secret never lands in repo history."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if skip := gitlab_only_skip(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    meta = snapshot.repo_meta if isinstance(snapshot.repo_meta, dict) else {}
    push_rule: Any = meta.get("_gitlab_push_rule")
    if not isinstance(push_rule, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Push-rule endpoint unavailable. The push-rule API "
                "is GitLab Premium / Ultimate; on Free / CE the "
                "endpoint returns 404 and the rule passes silently."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    prevent = bool(push_rule.get("prevent_secrets"))
    passed = prevent
    desc = (
        "Push rules block secret-shaped commits "
        "(``prevent_secrets: true``)."
        if passed else
        "Push rules do not block secret-shaped commits "
        "(``prevent_secrets: false`` or missing). A committer can "
        "push AWS / GCP credentials, SSH private keys, or "
        "credential-shaped filenames without server-side rejection; "
        "cleanup is retroactive at best."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
