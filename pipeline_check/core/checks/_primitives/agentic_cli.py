"""Shared detector for agentic-CLI invocations in a command body.

An agentic CLI reads a prompt and then *acts*: runs shell, writes files,
calls tools (``claude`` / ``gemini`` / ``cursor-agent`` / ``aider`` /
``openhands`` / ``goose`` / ``q chat``). That action capability is what
makes a prompt-injected agent dangerous, so the catalog is the *agentic*
CLIs specifically; plain text-completion CLIs (``llm``, ``ollama``) are
excluded because a prompt-injection there can't directly execute.
``q chat`` is Amazon Q; ``cursor-agent`` runs unattended by default.

Used by the GitHub agentic-AI rules (GHA-058 / 119 / 123, via the
``github/rules/_helpers`` re-export) and the GitLab analog GL-048.
"""
from __future__ import annotations

import re

# The agent name must be in command position: the ``(?<![\w./-])``
# look-behind excludes an identifier / path char before it, so a
# hyphenated filename (``run-gemini-benchmark.py``) or a path
# (``./gemini``) doesn't match, only a standalone command invocation.
AGENTIC_CLI_RE = re.compile(
    r"(?<![\w./-])(?:claude|gemini|q\s+chat|cursor-agent|aider|openhands|goose)\b",
    re.IGNORECASE,
)


def invokes_agentic_cli(body: str) -> str | None:
    """Return the agentic-CLI name *body* invokes (lowercased), or None."""
    match = AGENTIC_CLI_RE.search(body)
    return match.group(0).lower() if match else None
