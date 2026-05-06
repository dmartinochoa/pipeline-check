"""Rewrite standards docs to link bare check_id mentions to the
matching provider rule page.

Standards pages list each check_id as ``\\`GHA-001\\``` in the
mapping tables. After ``gen_provider_docs.py`` started pinning
``{ #gha-001 }`` anchors on every per-rule H2, those bare check_ids
have a stable click-through target. This script walks every
``docs/standards/*.md``, finds bare ``\\`<PREFIX>-<N>\\``` cells,
and rewrites them into markdown links.

Idempotent — re-running on a doc that's already been linked is a
no-op (the regex skips already-linked tokens).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
STANDARDS = REPO / "docs" / "standards"

# Provider rule-id prefix → provider doc slug.
# AWS service prefixes all route to providers/aws since rules under
# pipeline_check/core/checks/aws/rules/ cover the lot.
PREFIX_TO_PROVIDER: dict[str, str] = {
    # CI/CD providers
    "GHA": "github",
    "GL": "gitlab",
    "BB": "bitbucket",
    "ADO": "azure",
    "JF": "jenkins",
    "CC": "circleci",
    "GCB": "cloudbuild",
    "DF": "dockerfile",
    "K8S": "kubernetes",
    # IaC providers
    "TF": "terraform",
    "CF": "cloudformation",
    # AWS service prefixes — all rules live under providers/aws.md
    "IAM": "aws",
    "S3": "aws",
    "KMS": "aws",
    "CT": "aws",
    "CWL": "aws",
    "CW": "aws",
    "CCM": "aws",
    "CB": "aws",       # CodeBuild
    "CD": "aws",       # CodeDeploy
    "CP": "aws",       # CodePipeline
    "EB": "aws",       # EventBridge
    "LMB": "aws",      # Lambda
    "SM": "aws",       # Secrets Manager
    "SSM": "aws",      # Systems Manager Parameter Store
    "ECR": "aws",      # Elastic Container Registry
    "SIGN": "aws",     # Signer
    "CA": "aws",       # CodeArtifact
    "PBAC": "aws",     # Pipeline-Based Access Controls
}

# Match a backticked ``X-N`` token where X is one of the known
# provider prefixes. Skip tokens that are already inside a markdown
# link by anchoring to a space / pipe / line-start before the
# leading backtick. The negative lookbehind ``(?<!\])`` rejects
# ``](`X-N`)`` and similar pre-linked patterns.
_PREFIXES_RE = "|".join(re.escape(p) for p in PREFIX_TO_PROVIDER)
_BARE_CHECK_RE = re.compile(
    r"(?<![\w\]])"               # not following a word char or ``]``
    r"`(?P<id>(?P<prefix>"        # captures
    + _PREFIXES_RE +
    r")-\d{3})`"
)


#: Provider pages whose per-rule sections carry pinned anchors via
#: ``gen_provider_docs.py``. Linking ``../providers/<x>.md#<id>``
#: lands on the right rule. The other provider docs (AWS, Terraform,
#: CloudFormation) are hand-maintained without per-rule anchors;
#: those links target the page top instead.
_ANCHORED_PROVIDERS: frozenset[str] = frozenset({
    "github", "gitlab", "bitbucket", "azure", "jenkins", "circleci",
    "cloudbuild", "dockerfile", "kubernetes",
})


def _link_for(check_id: str, prefix: str) -> str:
    provider = PREFIX_TO_PROVIDER[prefix]
    # MkDocs resolves relative links by source file path. Source-side
    # we always live under ``docs/standards/<x>.md`` and want to
    # reach ``docs/providers/<y>.md``; emit the ``.md`` form so
    # mkdocs's link checker rewrites it to the correct rendered URL
    # (``/providers/<y>/#<anchor>`` under ``use_directory_urls=true``).
    if provider in _ANCHORED_PROVIDERS:
        anchor = check_id.lower()
        return f"[`{check_id}`](../providers/{provider}.md#{anchor})"
    return f"[`{check_id}`](../providers/{provider}.md)"


def _rewrite(text: str) -> tuple[str, int]:
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return _link_for(m.group("id"), m.group("prefix"))

    return _BARE_CHECK_RE.sub(_sub, text), count


def main() -> int:
    total = 0
    for path in sorted(STANDARDS.glob("*.md")):
        if path.name == "README.md":
            # Standards index — no mapping table to rewrite.
            continue
        original = path.read_text(encoding="utf-8")
        rewritten, hits = _rewrite(original)
        if hits == 0:
            print(f"[link-checks] {path.name}: no bare check_ids")
            continue
        path.write_text(rewritten, encoding="utf-8")
        total += hits
        print(f"[link-checks] {path.name}: linked {hits} check_id mention(s)")
    print(f"[link-checks] total: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
