"""PULUMI-007. Pulumi source declares a publicly accessible cloud resource."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-007",
    title="Pulumi source declares a publicly accessible cloud resource",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-S-LEAST-PRIV",),
    cwe=("CWE-732", "CWE-200"),
    recommendation=(
        "Remove the public-access setting from every flagged "
        "resource. Three remediation patterns by cloud:\n\n"
        "* AWS S3: set ``acl: aws.s3.BucketAcl.Private`` (or "
        "drop the ``acl:`` argument entirely; the default is "
        "private) and attach a bucket policy that names exactly "
        "the principals that need access. For static-content "
        "buckets, front the bucket with a CloudFront "
        "distribution + OAI rather than enabling public read.\n"
        "* Azure Blob: set ``publicAccess: 'None'`` on storage "
        "containers and grant access via SAS tokens / RBAC "
        "scoped to specific principals.\n"
        "* GCP Storage: drop ``predefinedAcl: 'publicRead'`` / "
        "``'publicReadWrite'`` and use IAM bindings scoped to "
        "the principals that need access. Public buckets in "
        "GCP also need uniform bucket-level access enabled to "
        "prevent ACL-driven escape.\n\n"
        "Where the resource genuinely needs public access "
        "(public-facing static site, public API), document the "
        "intent inline alongside the declaration and confirm "
        "the bucket / container content has no sensitive data."
    ),
    docs_note=(
        "Scans every source file in the Pulumi project root for "
        "high-confidence public-access patterns across the three "
        "major clouds:\n\n"
        "* AWS S3 bucket: ``acl: 'public-read'`` / "
        "``'public-read-write'``, ``aws.s3.BucketAcl.PublicRead``, "
        "or a ``BucketPolicy`` granting ``Principal: '*'``.\n"
        "* Azure Storage container: ``publicAccess: 'Container'`` "
        "/ ``'Blob'``.\n"
        "* GCP Storage bucket: ``predefinedAcl: 'publicRead'`` / "
        "``'publicReadWrite'``.\n\n"
        "Each pattern matches the canonical wire format so the "
        "false-positive surface is small. Patterns operate "
        "syntactically — a comment containing the literal "
        "``'public-read'`` won't trip the matcher unless the "
        "string also appears in a key-value position."
    ),
    known_fp=(
        "Public-facing static-content buckets that legitimately "
        "need public read access trip this rule by design. "
        "Suppress per source file with a one-line rationale "
        "naming the bucket's content type and the operator's "
        "review of the published data.",
    ),
    incident_refs=(
        "AWS S3 public-bucket disclosure incidents are a "
        "long-running pattern: misconfigured ACLs expose "
        "customer data, internal documents, and credential "
        "files to anyone with the bucket URL. Cloud providers' "
        "own audit reports rank public-bucket misconfigurations "
        "among the top sources of disclosure.",
    ),
    exploit_example=(
        "// Vulnerable: S3 bucket with public-read ACL.\n"
        "import * as aws from \"@pulumi/aws\";\n"
        "const bucket = new aws.s3.Bucket(\"data\", {\n"
        "    acl: \"public-read\",\n"
        "});\n"
        "\n"
        "// Attack: any file written to the bucket is fetchable\n"
        "// over the public internet via the bucket URL. A\n"
        "// downstream process that writes credential-shaped\n"
        "// data into the bucket (config exports, debug dumps,\n"
        "// log archives) becomes a public disclosure.\n"
        "\n"
        "// Safe: private ACL + scoped bucket policy.\n"
        "const bucket = new aws.s3.Bucket(\"data\", {\n"
        "    acl: aws.s3.BucketAcl.Private,\n"
        "});\n"
        "new aws.s3.BucketPolicy(\"data-policy\", {\n"
        "    bucket: bucket.id,\n"
        "    policy: pulumi.jsonStringify({\n"
        "        Statement: [{\n"
        "            Effect: \"Allow\",\n"
        "            Principal: { AWS: [trustedRole.arn] },\n"
        "            Action: [\"s3:GetObject\"],\n"
        "            Resource: [pulumi.interpolate`${bucket.arn}/*`],\n"
        "        }],\n"
        "    }),\n"
        "});"
    ),
)


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-s3-public-read-acl",
     re.compile(r'["\']?acl["\']?\s*[:=]\s*["\']public-read(?:-write)?["\']')),
    ("aws-s3-bucketacl-public",
     re.compile(r'BucketAcl\.PublicRead(?:Write)?\b')),
    ("aws-bucket-policy-wildcard-principal",
     re.compile(r'["\']?Principal["\']?\s*[:=]\s*["\']\*["\']')),
    ("azure-public-access-container",
     re.compile(r'["\']?publicAccess["\']?\s*[:=]\s*["\'](?:Container|Blob)["\']')),
    ("gcp-predefined-acl-public",
     re.compile(r'["\']?predefined[_]?[Aa]cl["\']?\s*[:=]\s*["\']publicRead(?:Write)?["\']')),
)


def check(ctx: PulumiContext) -> Finding:
    if not ctx.sources:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=(
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            ),
            description=(
                "No source files in the Pulumi project; nothing "
                "to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for source in ctx.sources:
        for label, pattern in _PATTERNS:
            for m in pattern.finditer(source.text):
                line_no = source.text[:m.start()].count("\n") + 1
                offenders.append(
                    f"{label} in {source.path}:{line_no}"
                )
                locations.append(Location(
                    path=source.path,
                    start_line=line_no, end_line=line_no,
                ))
                break  # one finding per (pattern, file) is enough
    passed = not offenders
    desc = (
        f"No public-access cloud-resource patterns across "
        f"{len(ctx.sources)} source file(s)."
        if passed else
        f"{len(offenders)} public-access cloud-resource "
        f"declaration(s): {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Anyone with "
        f"the resource URL can read (or write) without "
        f"authentication."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations
            else (ctx.projects[0].path if ctx.projects else "Pulumi.yaml")
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
