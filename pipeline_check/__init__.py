"""pipeline-check. CI/CD security posture scanner.

This module re-exports the small, stable surface library callers can
rely on. Anything not listed in ``__all__`` is internal and may move
between releases without notice.

Example
-------

    from pipeline_check import Scanner, Severity, score

    scanner = Scanner(pipeline="github", gha_path=".github/workflows")
    findings = scanner.run()
    critical = [f for f in findings if not f.passed and f.severity is Severity.CRITICAL]
    result = score(findings)
    print(f"score={result['score']} grade={result['grade']}")

The CLI entry point is :func:`pipeline_check.cli.main`; the AWS Lambda
entry point is :func:`pipeline_check.lambda_handler.handler`. Both of
those drive the same :class:`Scanner` you see above.
"""
# Single source of truth for the package version. The release script
# (see CLAUDE.md) bumps this literal alongside ``[project] version``
# in ``pyproject.toml`` and the ``vX.Y.Z`` git tag. We deliberately do
# NOT read ``importlib.metadata.version("pipeline_check")``: the
# installed dist-info goes stale on editable installs whenever
# someone bumps the version without re-running ``pip install -e .``,
# producing a misleading ``--version`` for contributors.
__version__ = "1.0.4"

# ── Public API surface ─────────────────────────────────────────────
#
# Re-exports below are versioned: types and functions named in
# ``__all__`` keep their import path stable across minor releases.
# Anything reached via deeper paths (``pipeline_check.core.*``) is
# internal and may move.

from .core.chains import Chain, ChainRule
from .core.chains import evaluate as evaluate_chains
from .core.chains import list_rules as list_chain_rules
from .core.checks.base import (
    Confidence,
    ControlRef,
    Finding,
    Location,
    Severity,
    confidence_rank,
    severity_rank,
)
from .core.checks.custom.loader import (
    CustomRuleError,
    LoadedCustomRules,
    load_custom_rules,
)
from .core.providers import available as available_providers
from .core.scanner import ScanMetadata, Scanner
from .core.scorer import ScoreResult, score
from .core.standards import available as available_standards

__all__ = [
    # Core entry point
    "Scanner",
    "ScanMetadata",
    # Findings + their building-block enums
    "Finding",
    "Location",
    "Severity",
    "Confidence",
    "ControlRef",
    "severity_rank",
    "confidence_rank",
    # Scoring
    "score",
    "ScoreResult",
    # Attack-chain correlation (read after Scanner.run())
    "Chain",
    "ChainRule",
    "evaluate_chains",
    "list_chain_rules",
    # Registry queries
    "available_providers",
    "available_standards",
    # Custom rule DSL
    "load_custom_rules",
    "LoadedCustomRules",
    "CustomRuleError",
    # Package metadata
    "__version__",
]
