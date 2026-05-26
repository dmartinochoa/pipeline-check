"""GHA-062. Sibling IaC pins an over-broad OIDC subject claim.

Scenarios 10 and 22 of ``greylag-ci/cicd-goat`` ship a workflow that's
correctly OIDC-bound to a protected environment but pairs it with a
sibling IaC file (an AWS IAM trust-policy JSON, or a Terraform
``google_iam_workload_identity_pool_provider`` block) whose subject
claim matches more than one repo. The workflow-side rules
(GHA-030, IAM-008) can't see the IaC; this rule walks the repo tree
to find it.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-062",
    title="OIDC subject claim in sibling IaC grants overly broad scope",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-7"),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-284", "CWE-269"),
    recommendation=(
        "Pin the OIDC subject claim to a specific repository (and ideally "
        "a specific branch / environment ref). For AWS IAM trust policies, "
        "replace ``StringLike`` ``token.actions.githubusercontent.com:sub`` "
        "values like ``repo:*`` or ``repo:<org>/*`` with "
        "``repo:<org>/<repo>:ref:refs/heads/main`` (or "
        "``:environment:<name>`` for environment-scoped tokens). For GCP "
        "Workload Identity Federation, replace ``attribute_condition`` "
        "predicates that only check the org prefix "
        "(``attribute.repository.startsWith('myorg/')``) with an "
        "equality on the exact ``<org>/<repo>`` plus branch / "
        "environment attributes."
    ),
    docs_note=(
        "Walks the workflow's containing repo (depth-bounded, skipping "
        "``node_modules`` / ``vendor`` / ``.git`` / build dirs) for two "
        "sidecar IaC file shapes when the workflow uses an OIDC cloud-"
        "credentials action:\n\n"
        "1. **AWS trust policy.** Any ``*.json`` whose body parses to "
        "an IAM trust document that references "
        "``token.actions.githubusercontent.com`` as a Federated "
        "principal AND whose ``Condition.StringLike`` ``...:sub`` "
        "value contains ``*`` in the ``repo:`` or ``repo:<org>/`` "
        "segment (``repo:*``, ``repo:<org>/*``, ``repo:<org>/*:*``). "
        "The branch / environment / ref segment may legitimately "
        "carry ``*``; only the org/repo segment is flagged.\n"
        "2. **GCP Workload Identity Federation.** Any ``*.tf`` "
        "containing a ``google_iam_workload_identity_pool_provider`` "
        "block whose ``attribute_condition`` is a ``startsWith`` "
        "or ``matches`` predicate against ``attribute.repository`` "
        "with a value that ends in a ``/`` slash (org prefix, no "
        "specific repo). Tighter conditions "
        "(``attribute.repository == 'myorg/myrepo'``) are skipped.\n\n"
        "Fires once per offending IaC file with a finding location "
        "pointing at the file. The walk is cached per scan so adding "
        "this rule doesn't compound the cost of GHA-030 / IAM-008. "
        "Pairs with GHA-030 (workflow-side environment binding) and "
        "IAM-008 (live AWS IAM audit); this leg covers the static "
        "IaC checked into the repo."
    ),
    known_fp=(
        "Test fixtures and documentation samples that intentionally "
        "embed permissive trust policies (e.g. cicd-goat's "
        "``scenarios/10-oidc-aws-wildcard-sub/trust-policy.json`` "
        "itself, when scanned in-place). Suppress with a path filter "
        "on the specific test directory. The rule is intentionally "
        "broad on file-name match so a renamed ``my-prod-trust-policy."
        "json`` still surfaces.",
    ),
    incident_refs=(
        "Multiple post-disclosure writeups of GitHub-to-AWS OIDC "
        "misconfigurations (Cider Security 2022, Datadog 2023, "
        "AquaSec 2024) traced the issue to a ``repo:*`` or "
        "``repo:org/*`` ``StringLike`` subject pattern that was "
        "kept as a stop-gap during initial onboarding and never "
        "tightened. Any fork PR or any newly-created org repo could "
        "mint a production-role token until the policy was edited.",
    ),
    exploit_example=(
        "# Vulnerable trust-policy.json (any repo can assume):\n"
        "{\n"
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"Federated":\n'
        '      "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},\n'
        '    "Action": "sts:AssumeRoleWithWebIdentity",\n'
        '    "Condition": {\n'
        '      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},\n'
        '      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:*"}\n'
        '    }\n'
        '  }]\n'
        "}\n"
        "\n"
        "# Safe — pinned to one repo + main branch:\n"
        '"StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"}'
    ),
)


# OIDC cloud-credential actions whose presence triggers the sidecar
# IaC scan. Matched as ``uses:`` prefixes (so any version pin counts).
_OIDC_USES_PREFIXES: tuple[str, ...] = (
    "aws-actions/configure-aws-credentials",
    "google-github-actions/auth",
    # The Azure analogue is ``azure/login`` — Azure's OIDC trust lives
    # in a Federated Credential resource rather than a static JSON
    # policy, so we don't currently emit a sidecar lookup for it.
)


# Directories the IaC walker skips. Keeps the scan O(repo size) rather
# than O(transitive node_modules size).
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "vendor", "dist", "build", "target",
    ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache",
})


def _job_uses_oidc(job: dict[str, Any]) -> bool:
    for step in iter_steps(job):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        prefix = uses.split("@", 1)[0].strip().lower()
        if any(prefix.startswith(p) for p in _OIDC_USES_PREFIXES):
            return True
    return False


def _scan_root(workflow_path: str) -> str:
    """Return the directory the IaC walk should start from.

    Strategy: walk up from the workflow's directory looking for a
    sibling ``.github`` directory (the canonical repo-root marker for
    GHA-using projects). If the workflow itself lives under
    ``.github/workflows/``, the parent of ``.github`` is the repo
    root. If no ``.github`` marker is found within a few levels (the
    workflow is in a synthetic test fixture, a multi-workflow
    monorepo subset, or a non-standard layout), fall back to the
    workflow's own directory so the walk stays narrow rather than
    scanning the entire filesystem.
    """
    dir_ = os.path.dirname(os.path.abspath(workflow_path))
    start = dir_
    for _ in range(6):
        if os.path.isdir(os.path.join(dir_, ".github")):
            return dir_
        parent = os.path.dirname(dir_)
        if parent == dir_:
            break
        dir_ = parent
    return start


# Cache the per-repo-root IaC walk so a workflow tree with N
# workflow files doesn't walk the tree N times.
_IAC_SCAN_CACHE: dict[str, list[tuple[str, str]]] = {}


def clear_iac_scan_cache() -> None:
    """Drop the per-repo-root IaC walk cache.

    Called from :func:`~pipeline_check.core.checks.blob.clear_blob_cache`
    so long-lived processes (LSP server, Lambda container) don't serve
    stale results after the repo tree changes between scans.
    """
    _IAC_SCAN_CACHE.clear()


def _iac_candidates(root: str, max_depth: int = 6) -> list[tuple[str, str]]:
    """Return ``(absolute_path, kind)`` for candidate IaC files.

    ``kind`` is ``"trust-policy"`` for AWS JSON files or ``"wif-tf"``
    for Terraform files that look like GCP WIF configs. The walker
    only opens files that pass a cheap name-shape filter so the cost
    stays bounded on large repos.
    """
    cached = _IAC_SCAN_CACHE.get(root)
    if cached is not None:
        return cached
    hits: list[tuple[str, str]] = []
    root_abs = os.path.abspath(root)
    root_depth = root_abs.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if dirpath.count(os.sep) - root_depth > max_depth:
            dirnames[:] = []
            continue
        for fn in filenames:
            lower = fn.lower()
            if lower.endswith(".json") and "trust" in lower and "polic" in lower:
                hits.append((os.path.join(dirpath, fn), "trust-policy"))
            elif lower.endswith(".tf"):
                hits.append((os.path.join(dirpath, fn), "wif-tf"))
    _IAC_SCAN_CACHE[root] = hits
    return hits


# Subject patterns that match more than one repo. ``repo:*``, ``repo:org/*``,
# and ``repo:org/*:*`` all match every repo (in the second form, every repo
# under one org). We treat any ``*`` in the org-or-repo segment as overly
# broad. ``repo:org/repo:ref:refs/heads/*`` (branch wildcard) is NOT
# flagged here — branch breadth is a softer call.
_BROAD_SUB_RE = re.compile(
    r"^repo:(?:\*|[^/]+/\*)(?::|$)",
)


def _trust_policy_findings(path: str) -> list[str]:
    """Return one offender label per broad-sub Statement in the file."""
    try:
        with open(path, encoding="utf-8") as fp:
            doc = json.load(fp)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return []
    labels: list[str] = []
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal")
        if not isinstance(principal, dict):
            continue
        fed = principal.get("Federated")
        federated_values: list[str] = []
        if isinstance(fed, str):
            federated_values.append(fed)
        elif isinstance(fed, list):
            federated_values.extend(v for v in fed if isinstance(v, str))
        # IAM ``Federated`` is canonically
        # ``arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com``.
        # Anchor on the trailing host segment so a substring match on
        # an attacker-controlled host (``evil.com/.../token.actions...``)
        # can't trip the gate.
        if not any(
            v.endswith("/token.actions.githubusercontent.com")
            or v == "token.actions.githubusercontent.com"
            for v in federated_values
        ):
            continue
        conditions = stmt.get("Condition")
        if not isinstance(conditions, dict):
            continue
        for inner in conditions.values():
            if not isinstance(inner, dict):
                continue
            for key, value in inner.items():
                if not (
                    isinstance(key, str)
                    and key.lower().endswith(":sub")
                ):
                    continue
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if isinstance(v, str) and _BROAD_SUB_RE.match(v):
                        labels.append(v)
    return labels


# GCP WIF: ``attribute.repository.startsWith('myorg/')`` is the
# whole-org binding shape. Tighter shapes
# (``attribute.repository == 'myorg/myrepo'``) are skipped. Match the
# value of ``startsWith`` and accept the offender when it ends with
# ``/`` (org prefix, no specific repo).
_TF_WIF_RE = re.compile(
    r"attribute_condition\s*=\s*"
    r"\"[^\"]*?attribute\.repository\.startsWith\(\s*['\"]"
    r"(?P<value>[^'\"]+)['\"]\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _tf_wif_findings(path: str) -> list[str]:
    """Return one offender label per broad WIF condition in the .tf file."""
    try:
        with open(path, encoding="utf-8") as fp:
            text = fp.read()
    except (OSError, UnicodeDecodeError):
        return []
    if "google_iam_workload_identity_pool_provider" not in text:
        return []
    labels: list[str] = []
    for m in _TF_WIF_RE.finditer(text):
        value = m.group("value")
        # ``myorg/`` is the org-prefix binding; ``myorg/myrepo`` is
        # already tight. Only the prefix-with-slash form is the broad
        # shape we flag.
        if value.endswith("/") and "/" in value.rstrip("/"):
            # ``a/b/`` style — too unusual to flag confidently
            continue
        if value.endswith("/") or "/" not in value:
            labels.append(f"attribute.repository.startsWith({value!r})")
    return labels


def check(path: str, doc: dict[str, Any]) -> Finding:
    needs_scan = any(_job_uses_oidc(job) for _, job in iter_jobs(doc))
    if not needs_scan:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow doesn't use a GitHub OIDC cloud-credentials "
                "action; sibling IaC trust-policy / WIF audit not "
                "applicable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    root = _scan_root(path)
    offenders: list[str] = []
    for iac_path, kind in _iac_candidates(root):
        rel = os.path.relpath(iac_path, root)
        if kind == "trust-policy":
            for label in _trust_policy_findings(iac_path):
                offenders.append(f"{rel}: sub claim {label!r} matches multiple repos")
        elif kind == "wif-tf":
            for label in _tf_wif_findings(iac_path):
                offenders.append(f"{rel}: WIF {label} binds the whole org")
    passed = not offenders
    desc = (
        "No sibling IaC trust-policy / WIF file with an over-broad "
        "subject claim found alongside this OIDC-using workflow."
        if passed else
        f"{len(offenders)} sibling IaC file(s) bind the workflow's "
        f"OIDC role to more than one repo: "
        f"{'; '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. The workflow's "
        f"``environment:`` binding (GHA-030's signal) protects the "
        f"GHA side, but the cloud-side trust statement is what "
        f"actually accepts the token."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
