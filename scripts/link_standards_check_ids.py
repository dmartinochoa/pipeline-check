"""Rewrite standards docs to link bare check_id mentions to the
matching provider rule page.

Standards pages list each check_id as ``\\`GHA-001\\``` in the
mapping tables. After ``gen_provider_docs.py`` started pinning
``{ #gha-001 }`` anchors on every per-rule H2, those bare check_ids
have a stable click-through target. This script walks every
``docs/standards/*.md``, finds bare ``\\`<PREFIX>-<N>\\``` cells,
and rewrites them into markdown links.

Idempotent: re-running on a doc that's already been linked is a
no-op (the regex skips already-linked tokens, and operation is
scoped to mapping-table rows so prose / headings / code spans are
never touched). The ``--check`` flag exits 1 if any doc would
change, useful as a CI drift guard.
"""
from __future__ import annotations

import argparse
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
    # SCM posture (rules live in scm_github.md)
    "SCM": "scm_github",
    # IaC providers
    "TF": "terraform",
    "CF": "cloudformation",
    # AWS service prefixes, all rules live under providers/aws.md
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
# link in either shape:
#   - text-of-link    : ``[`X-N`](url)``        leading ``[`` + trailing ``]``
#   - target-of-link  : ``[label](`X-N`)``      leading ``(`` is also rejected
#
# The lookbehind rejects ``[`` / ``]`` / word-char before the opening
# backtick (catches text-of-link and adjacent identifiers). The
# lookahead rejects ``]`` after the closing backtick (defense in
# depth: in-page anchor links emitted by ``gen_standards_docs.py``
# look like ``[`X-N`](#detail-x-n)`` — both negations apply, so the
# linker is a strict no-op on the generator's output).
_PREFIXES_RE = "|".join(re.escape(p) for p in PREFIX_TO_PROVIDER)
_BARE_CHECK_RE = re.compile(
    r"(?<![\w\[\]])"             # not following a word char or ``[`` / ``]``
    r"`(?P<id>(?P<prefix>"        # captures
    + _PREFIXES_RE +
    r")-\d{3})`"
    r"(?!\])"                     # closing backtick must not be followed by ``]``
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
    """Scope: mapping-table rows only.

    The script's design intent (per its docstring) is to make bare
    check_id mentions in standards mapping tables clickable. Prose,
    H3 detail headings emitted by ``gen_standards_docs.py``, and
    double-backtick code spans (``\\`\\`X-N\\`\\``) were never in
    scope — touching them either corrupts surrounding markup or
    duplicates a link the generator already emits two lines later
    (``**Source:** [\\`X-N\\`](...)`` sits right under every detail
    heading). Restricting to ``lstrip().startswith("|")`` lines
    makes the linker a strict no-op against the generator's current
    output while preserving the original purpose.
    """
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return _link_for(m.group("id"), m.group("prefix"))

    out: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("|"):
            out.append(_BARE_CHECK_RE.sub(_sub, line))
        else:
            out.append(line)
    return "".join(out), count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any standards doc would be rewritten. Useful in CI.",
    )
    args = parser.parse_args()

    total = 0
    stale: list[str] = []
    for path in sorted(STANDARDS.glob("*.md")):
        if path.name == "README.md":
            # Standards index, no mapping table to rewrite.
            continue
        original = path.read_text(encoding="utf-8")
        rewritten, hits = _rewrite(original)
        if hits == 0:
            print(f"[link-checks] {path.name}: no bare check_ids")
            continue
        if args.check:
            stale.append(path.name)
            print(
                f"[link-checks] {path.name}: would rewrite {hits} "
                f"check_id mention(s)",
                file=sys.stderr,
            )
            continue
        path.write_text(rewritten, encoding="utf-8")
        total += hits
        print(f"[link-checks] {path.name}: linked {hits} check_id mention(s)")

    if args.check and stale:
        print(
            f"[link-checks] {len(stale)} standards doc(s) need linking. "
            f"Re-run scripts/link_standards_check_ids.py to update.",
            file=sys.stderr,
        )
        return 1
    if not args.check:
        print(f"[link-checks] total: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
