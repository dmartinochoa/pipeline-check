"""AWS rule modules — auto-discovered by ``AWSRuleChecks``.

Each rule module exports:

- ``RULE``: a :class:`pipeline_check.core.checks.rule.Rule` instance
  carrying stable metadata (id, title, severity, recommendation, prose).
- ``check(catalog)``: a callable that receives a
  :class:`pipeline_check.core.checks.aws._catalog.ResourceCatalog` and
  returns a ``list[Finding]``.

Adding a check is a one-file change: drop ``<id>_<slug>.py`` here and
both the orchestrator and the provider doc generator pick it up.
"""
