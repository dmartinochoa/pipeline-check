"""PULUMI-004. Pulumi project uses an insecure state backend."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-004",
    title="Pulumi project uses an insecure state backend",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-319", "CWE-922"),
    recommendation=(
        "Move the state backend off the insecure URL. Three "
        "stable options:\n\n"
        "* ``app.pulumi.com`` (the default; no ``backend.url`` "
        "needed). Audit trail + per-stack ACLs + encrypted-at-"
        "rest state.\n"
        "* ``s3://<bucket>?region=<region>`` with bucket-level "
        "default encryption + bucket policy that gates "
        "``GetObject`` to the deploy IAM principal.\n"
        "* ``azblob://<container>`` or ``gs://<bucket>`` with the "
        "equivalent Azure / GCP-side encryption + IAM gates.\n\n"
        "Avoid ``file://`` (local disk; no portability, no audit, "
        "lost on runner teardown) and plain ``http://`` (in-flight "
        "state transit unencrypted; tampering by anyone on the "
        "network path). Run ``pulumi login <new-backend>`` and "
        "follow the migration prompts; existing state files "
        "transfer with secrets preserved."
    ),
    docs_note=(
        "Reads ``backend.url`` from every ``Pulumi.yaml`` and "
        "fires on:\n\n"
        "* ``file://<path>`` — local-disk backend; state lives "
        "alongside the working tree, lost on runner teardown, no "
        "audit log\n"
        "* ``http://<host>/...`` — plain HTTP transport; state "
        "operations (init, refresh, push) leak full state body "
        "+ secret payloads to any MITM\n\n"
        "Absent ``backend`` field is the Pulumi-service default "
        "(safe posture, audited + encrypted) and passes the rule. "
        "HTTPS / ``s3://`` / ``gs://`` / ``azblob://`` / "
        "``hashivault://`` URLs also pass.\n\n"
        "The rule operates on the manifest text only; it does "
        "not verify backend reachability or the configured "
        "credentials."
    ),
    known_fp=(
        "Local-only development sandboxes deliberately use "
        "``file://`` so the engineer can iterate without "
        "configuring a backend. The rule still fires; suppress "
        "per file with a one-line rationale naming the sandbox "
        "policy when the project is genuinely local-only.",
    ),
    incident_refs=(
        "Pattern of CI runners writing ``file://``-backed Pulumi "
        "state to ephemeral disk between deploys: the state is "
        "lost on runner teardown, the next ``pulumi up`` "
        "rebuilds infrastructure from scratch (deleting and "
        "recreating production resources) because Pulumi has no "
        "state to reconcile against. The plain-HTTP case is "
        "rarer in production but surfaces in self-hosted "
        "configurations where an HTTPS reverse proxy was "
        "supposed to terminate in front of the backend service.",
    ),
    exploit_example=(
        "# Vulnerable: file:// backend on a CI runner.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: python\n"
        "backend:\n"
        "  url: file:///opt/pulumi/state\n"
        "\n"
        "# Risk: the runner image's /opt/pulumi/state is\n"
        "# ephemeral. Every fresh runner starts with no state\n"
        "# file; ``pulumi up`` interprets the missing state as\n"
        "# 'create everything from scratch' and tries to\n"
        "# re-create resources that already exist in the cloud.\n"
        "# Best case: the deploy fails with 'resource already\n"
        "# exists'. Worst case: the cloud SDK supports\n"
        "# create-or-update and silently overwrites running\n"
        "# resources.\n"
        "\n"
        "# Safe: cloud-managed backend with encryption + IAM.\n"
        "# Pulumi.yaml\n"
        "name: my-app\n"
        "runtime: python\n"
        "backend:\n"
        "  url: s3://my-pulumi-state?region=us-east-1\n"
        "\n"
        "# State is encrypted at rest (S3 bucket default\n"
        "# encryption), gated by IAM, and audited via\n"
        "# CloudTrail. The runner needs only ``s3:GetObject`` /\n"
        "# ``s3:PutObject`` on the bucket prefix."
    ),
)


def check(ctx: PulumiContext) -> Finding:
    if not ctx.projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="Pulumi.yaml",
            description="No Pulumi.yaml in the scan path.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for project in ctx.projects:
        url = project.backend_url
        if url is None:
            # No explicit backend = Pulumi-service default = safe.
            continue
        bad = False
        if url.startswith("file://"):
            bad = True
            label = "file://"
        elif url.startswith("http://"):
            bad = True
            label = "http://"
        else:
            label = ""
        if bad:
            offenders.append(f"{project.path} ({label}{url[7:]})")
            # Best-effort line: search the text for ``url:``.
            line_no = 1
            if "url:" in project.text:
                line_no = (
                    project.text[:project.text.index("url:")].count("\n") + 1
                )
            locations.append(Location(
                path=project.path,
                start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "Every Pulumi.yaml uses a secure state backend "
        "(Pulumi-service default, HTTPS, or cloud blob storage)."
        if passed else
        f"{len(offenders)} Pulumi.yaml use an insecure backend: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``file://`` is "
        f"non-portable + unaudited; ``http://`` exposes state "
        f"in transit."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations else ctx.projects[0].path
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
