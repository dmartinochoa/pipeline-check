"""Curated top-actions list and edit-distance typosquat classifier.

Shared between GHA-088 (``uses:`` typosquat) and any future rule
that needs to ask "is this ``owner/repo`` slug a near-miss of a
high-traffic GitHub Action?". The data side is hand-curated; the
algorithm side is a small Damerau-Levenshtein implementation with a
hard ceiling so the rule stays linear in the workflow body.

The list intentionally undersells coverage. It is biased toward the
actions that anchor first-party CI on GitHub (the ones a typo of
which is most likely to compile under reviewer eyes). Less-trafficked
actions are out of scope, edit-distance on a long tail produces
false positives that drown the rule. Refresh by PR with a citing
public-stats source in the commit message.
"""
from __future__ import annotations

# Curated list of high-traffic actions. Canonical form is
# ``owner/repo`` lowercased. Both sides are compared as a single
# string with the slash included; distance on ``actions/check0ut``
# vs ``actions/checkout`` is 1, distance on ``actons/checkout`` is
# also 1, and ``actions-checkout/checkout`` vs ``actions/checkout``
# is 9 (owner change) which falls outside the ceiling.
#
# Stable ordering: alphabetical, makes review diffs predictable.
TOP_ACTIONS: tuple[str, ...] = (
    "actions/cache",
    "actions/checkout",
    "actions/configure-pages",
    "actions/create-github-app-token",
    "actions/dependency-review-action",
    "actions/deploy-pages",
    "actions/download-artifact",
    "actions/first-interaction",
    "actions/github-script",
    "actions/jekyll-build-pages",
    "actions/labeler",
    "actions/setup-dotnet",
    "actions/setup-go",
    "actions/setup-java",
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-ruby",
    "actions/stale",
    "actions/upload-artifact",
    "actions/upload-pages-artifact",
    "aquasecurity/trivy-action",
    "arduino/setup-protoc",
    "arduino/setup-task",
    "aws-actions/amazon-ecr-login",
    "aws-actions/configure-aws-credentials",
    "azure/cli",
    "azure/login",
    "azure/setup-kubectl",
    "benc-uk/workflow-dispatch",
    "codecov/codecov-action",
    "crazy-max/ghaction-import-gpg",
    "dawidd6/action-download-artifact",
    "denoland/setup-deno",
    "docker/build-push-action",
    "docker/login-action",
    "docker/metadata-action",
    "docker/setup-buildx-action",
    "docker/setup-qemu-action",
    "dorny/paths-filter",
    "EndBug/add-and-commit",
    "fountainhead/action-wait-for-check",
    "github/codeql-action",
    "github/super-linter",
    "gitleaks/gitleaks-action",
    "google-github-actions/auth",
    "google-github-actions/get-gke-credentials",
    "google-github-actions/setup-gcloud",
    "goreleaser/goreleaser-action",
    "gradle/gradle-build-action",
    "gradle/wrapper-validation-action",
    "hashicorp/setup-terraform",
    "JamesIves/github-pages-deploy-action",
    "JS-DevTools/npm-publish",
    "microsoft/setup-msbuild",
    "mikepenz/action-junit-report",
    "ncipollo/release-action",
    "oven-sh/setup-bun",
    "peaceiris/actions-gh-pages",
    "peter-evans/create-or-update-comment",
    "peter-evans/create-pull-request",
    "peter-evans/repository-dispatch",
    "pnpm/action-setup",
    "pre-commit/action",
    "pypa/gh-action-pypi-publish",
    "release-drafter/release-drafter",
    "ruby/setup-ruby",
    "rust-lang/setup-rust-toolchain",
    "shivammathur/setup-php",
    "sigstore/cosign-installer",
    "slackapi/slack-github-action",
    "snyk/actions",
    "softprops/action-gh-release",
    "stefanzweifel/git-auto-commit-action",
    "step-security/harden-runner",
    "subosito/flutter-action",
    "swift-actions/setup-swift",
    "thollander/actions-comment-pull-request",
    "tibdex/github-app-token",
    "treosh/lighthouse-ci-action",
    "wagoid/commitlint-github-action",
)


#: Lowercased lookup set for O(1) exact-match short-circuit.
_TOP_ACTIONS_LOWER: frozenset[str] = frozenset(a.lower() for a in TOP_ACTIONS)


def _damerau_levenshtein(a: str, b: str, ceiling: int) -> int:
    """Edit distance between *a* and *b*, capped at *ceiling*.

    Once any partial distance exceeds *ceiling*, the function returns
    ``ceiling + 1`` so the caller short-circuits. Implements
    Damerau-Levenshtein (single-pair transposition counts as one
    edit), which is the right shape for typosquat. Quadratic in the
    string lengths but the inputs are short (<= 60 chars on the
    ``owner/repo`` slugs the rule passes in).
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > ceiling:
        return ceiling + 1
    # Two-row Damerau-Levenshtein is awkward; the trade-off here is
    # full O(la*lb) memory for the small inputs we deal with, which
    # is fine.
    prev2: list[int] = []
    prev: list[int] = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        row_min = curr[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
            if (
                i > 1 and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                curr[j] = min(curr[j], prev2[j - 2] + 1)
            if curr[j] < row_min:
                row_min = curr[j]
        if row_min > ceiling:
            return ceiling + 1
        prev2 = prev
        prev = curr
    return prev[lb]


def find_typosquat(slug: str, max_distance: int = 2) -> str | None:
    """Return the top-action *slug* matches as a near-miss, or ``None``.

    A slug that is an *exact* member of the curated list is not a
    typosquat (the canonical action itself); returns ``None``.

    A slug with edit-distance ``1..max_distance`` to any list entry
    is a typosquat candidate; returns the closest list entry (ties
    broken by lexicographic order for determinism).

    Distances strictly above ``max_distance`` return ``None``; the
    rule does not fire on far-away names.
    """
    if not slug:
        return None
    candidate = slug.lower()
    if candidate in _TOP_ACTIONS_LOWER:
        return None
    best: tuple[int, str] | None = None
    for top in TOP_ACTIONS:
        d = _damerau_levenshtein(candidate, top.lower(), max_distance)
        if 0 < d <= max_distance:
            if best is None or (d, top) < best:
                best = (d, top)
    return best[1] if best else None
