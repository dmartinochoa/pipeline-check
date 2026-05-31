"""GHA-005. AWS auth should use OIDC, not long-lived access keys."""
from __future__ import annotations

import re as _re
from typing import Any

from ..._primitives.local_mock import env_has_localstack_sentinel
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-005",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Use `aws-actions/configure-aws-credentials` with "
        "`role-to-assume` + `permissions: id-token: write` to obtain "
        "short-lived credentials via OIDC. Remove the static "
        "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "secrets in GitHub Actions can't be rotated on a fine-"
        "grained schedule and remain valid until manually revoked. "
        "OIDC with `role-to-assume` yields short-lived credentials "
        "per workflow run."
    ),
    known_fp=(
        "LocalStack and Moto integration tests set "
        "``AWS_ENDPOINT_URL`` to a localhost address and use the "
        "sentinel ``test`` / ``test`` access keys (the LocalStack "
        "convention). Those values can't authenticate against real "
        "AWS, so the rule auto-suppresses an env block that pairs a "
        "localhost endpoint with sentinel keys.",
    ),
    exploit_example=(
        "# Vulnerable: long-lived IAM user keys, even sourced from secrets.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
        "          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"
        "          aws-region: us-east-1\n"
        "\n"
        "# Attack: the keys land in the runner environment and\n"
        "# ~/.aws/credentials. A later step running untrusted code (a\n"
        "# compromised third-party action, an injected `run:`, a\n"
        "# malicious transitive dependency) reads and exfiltrates them.\n"
        "# Because they're long-lived IAM user keys, the attacker keeps\n"
        "# AWS access until someone notices and rotates them by hand.\n"
        "\n"
        "# Safe: OIDC. The assumed-role credential expires within the\n"
        "# hour and is scoped to this run.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123456789012:role/ci-deploy\n"
        "          aws-region: us-east-1"
    ),
)


_AWS_CONFIGURE_RE = _re.compile(
    r"aws\s+configure\s+set\s+aws_access_key_id\b"
    r"|aws\s+configure\s+set\s+aws_secret_access_key\b"
)

_SECRETS_REF_RE = _re.compile(r"\$\{\{\s*secrets\.")


def _env_has_static_key(env: Any) -> bool:
    """True if an env block sets AWS key vars to non-secrets references."""
    if not isinstance(env, dict):
        return False
    if env_has_localstack_sentinel(env):
        return False
    for key, value in env.items():
        key_s = str(key).upper()
        if key_s not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            continue
        if isinstance(value, str) and not _SECRETS_REF_RE.search(value):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    oidc_role = False
    locations: list[Location] = []
    # Preserve insertion order without duplicates. Job-level and step-
    # level static keys anchor to the containing job; workflow-level
    # env applies to every job (GitHub inherits ``env:`` declared at
    # the top into each job's environment) so workflow-scope leaks are
    # unioned with every job_id at the end. The reachability-aware
    # AC-003 chain intersects these with GHA-001's unpinned-action jobs
    # to confirm the credential-exfil path.
    anchor_jobs: dict[str, None] = {}
    all_job_ids: list[str] = []

    def _flag_static(anchor: Any, job_id: str | None) -> None:
        """Mark static-key found and record a Location at *anchor*."""
        nonlocal static_keys
        static_keys = True
        if isinstance(anchor, dict):
            line = _line_of(anchor)
            locations.append(Location(path=path, start_line=line, end_line=line))
        if job_id is not None:
            anchor_jobs[job_id] = None

    for job_id, job in iter_jobs(doc):
        all_job_ids.append(job_id)
        # Check job-level env for non-secrets AWS key assignments.
        if _env_has_static_key(job.get("env")):
            _flag_static(job.get("env"), job_id)
        for step in iter_steps(job):
            uses = step.get("uses") or ""
            if isinstance(uses, str) and uses.startswith(
                "aws-actions/configure-aws-credentials@"
            ):
                w = step.get("with") or {}
                if "role-to-assume" in w:
                    oidc_role = True
                if "aws-access-key-id" in w or "aws-secret-access-key" in w:
                    static_keys = True
                    locations.append(step_location(path, step))
                    anchor_jobs[job_id] = None
            env = step.get("env") or {}
            if isinstance(env, dict):
                for value in env.values():
                    if isinstance(value, str) and (
                        "AWS_ACCESS_KEY_ID" in value
                        or "AWS_SECRET_ACCESS_KEY" in value
                    ):
                        _flag_static(env, job_id)
                        break
            # Detect `aws configure set aws_access_key_id ...` in run blocks.
            run = step.get("run")
            if isinstance(run, str) and _AWS_CONFIGURE_RE.search(run):
                static_keys = True
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
            # Check step-level env for non-secrets AWS key assignments.
            if _env_has_static_key(step.get("env")):
                _flag_static(step.get("env"), job_id)
    doc_env = doc.get("env") or {}
    wf_env_static = False
    if isinstance(doc_env, dict):
        for value in doc_env.values():
            if isinstance(value, str) and (
                "AWS_ACCESS_KEY_ID" in value
                or "AWS_SECRET_ACCESS_KEY" in value
            ):
                _flag_static(doc_env, None)
                wf_env_static = True
                break
    if _env_has_static_key(doc_env):
        _flag_static(doc_env, None)
        wf_env_static = True
    # Workflow-level env inherits into every job, so the credential
    # is reachable from any job. Anchor on all job_ids accordingly.
    if wf_env_static:
        for jid in all_job_ids:
            anchor_jobs[jid] = None
    if not static_keys and not oidc_role:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow does not configure AWS credentials.",
            recommendation="No action required.", passed=True,
        )
    passed = oidc_role and not static_keys
    if passed:
        desc = "AWS credentials are obtained via OIDC (`role-to-assume`)."
    elif static_keys:
        desc = (
            "Workflow authenticates to AWS with long-lived access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) via static "
            "env vars, `aws configure`, or action inputs. These can't be "
            "rotated on a fine-grained schedule and remain valid until "
            "manually revoked."
        )
    else:
        desc = "AWS credential configuration detected but could not be classified."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations if not passed else [],
        job_anchors=tuple(anchor_jobs) if not passed else (),
    )
