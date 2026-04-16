"""Lock in that Scanner resets the secret-pattern registry per run.

Long-lived Lambda containers reuse the module-level `_PATTERNS` list;
without this reset, patterns registered for one invocation pollute
the next.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from pipeline_check.core import providers as providers_mod
from pipeline_check.core.checks import _secrets as secrets_mod
from pipeline_check.core.scanner import Scanner


def test_scanner_resets_registry_between_constructions(monkeypatch, tmp_path):
    """A pattern registered via Scanner(secret_patterns=…) for one scan
    must not survive into the next Scanner() with no patterns."""
    # Fake provider so we don't need real AWS creds / real YAML on disk.
    fake_context = MagicMock()
    fake_provider = MagicMock()
    fake_provider.check_classes = []
    fake_provider.build_context.return_value = fake_context
    monkeypatch.setattr(providers_mod, "get", lambda _name: fake_provider)

    # First scan registers a custom pattern. ``_PATTERNS`` now holds
    # ONLY user-supplied patterns (built-ins live in SECRET_DETECTORS).
    Scanner(pipeline="aws", secret_patterns=["^acme_[a-f0-9]{32}$"])
    assert len(secrets_mod._PATTERNS) == 1
    assert secrets_mod._PATTERNS[0].pattern == "^acme_[a-f0-9]{32}$"

    # Second scan with no patterns — registry must be empty so the
    # acme pattern doesn't leak into this invocation.
    Scanner(pipeline="aws")
    assert secrets_mod._PATTERNS == []
