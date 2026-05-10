"""SCM (source control management) posture provider.

Scans GitHub repository governance — branch protection, required
reviews, code scanning, secret scanning, runner-group restrictions —
that the existing GHA workflow rule pack doesn't see because it
lives at the repository / org settings layer rather than in workflow
YAML. Maps each rule to OpenSSF Scorecard check IDs so the catalog
slots into existing supply-chain compliance work.

The provider hits the GitHub REST API on demand. The caller supplies
the token (``--gh-token`` or ``$GITHUB_TOKEN``); failed API calls
land in ``ctx.warnings`` rather than raising. A
``--scm-fixture-dir`` flag reads JSON responses from disk for
offline / CI-fixture testing without holding a real token.

This is the same architectural seam the GHA reusable-workflow
resolver uses: a ``RemoteFetcher`` Protocol with HTTP and disk
implementations, swappable for tests via a ``FakeFetcher`` from the
test suite.
"""
