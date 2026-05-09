"""AI-augmented finding explanation.

Opt-in only. The deterministic ``--explain`` body is ALWAYS what
the CI gate, score, and audit trail consume; this module sits
strictly on top of that surface and adds a clearly-marked
``[AI-generated]`` section the operator can read for triage.

The boundary is load-bearing. The whole tool's contract — same
input always produces the same output — would be undermined by
mixing LLM output into the deterministic path. So:

- AI explanations never affect ``Finding`` / ``Score`` / ``Gate``.
- The ``--ai-explain`` flag is mutually exclusive with running a
  scan.
- The output is framed with an ``[AI-generated]`` banner so a
  reader who pastes the response into a ticket / PR comment knows
  what to attribute.

Three providers, all opt-in:

- ``anthropic:claude-sonnet-4-6`` (default if ``ANTHROPIC_API_KEY``
  is set). Uses the official ``anthropic`` SDK lazy-imported.
- ``openai:gpt-4o-mini``. Uses the official ``openai`` SDK lazy-
  imported.
- ``ollama:llama3.2``. Uses ``urllib.request`` against a local
  Ollama daemon — no extra Python dependencies, no API key.

SDK deps are optional extras (``pip install pipeline-check[ai-anthropic]``
or ``[ai-openai]``); the default install carries no AI surface at
all, so a runtime that never opts in pulls zero net new bytes.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .checks.rule import Rule


class AIDependencyError(RuntimeError):
    """The selected provider's optional dependency isn't installed."""


class AIAuthError(RuntimeError):
    """The selected provider has no credentials configured."""


class AIRequestError(RuntimeError):
    """The provider returned a non-recoverable error."""


@runtime_checkable
class AIClient(Protocol):
    """One-shot chat completion. ``name`` is a stable label for
    output framing (e.g. ``anthropic:claude-sonnet-4-6``)."""

    name: str

    def complete(self, system: str, user: str) -> str:
        """Return the model's response text. Raises on failure."""
        ...


@dataclass(frozen=True, slots=True)
class _ModelSpec:
    provider: str
    model: str


# Default model per provider. Picked for "good fast cheap default":
# the goal is short remediation prose grounded in 200 lines of
# context, not deep reasoning.
_DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.2",
}


def _parse_spec(spec: str) -> _ModelSpec:
    """Parse ``provider[:model]`` into a structured spec.

    The bare-provider form (e.g. ``anthropic``) picks the default
    model from :data:`_DEFAULT_MODELS`. An explicit colon
    (``anthropic:claude-opus-4-7``) overrides.
    """
    if ":" in spec:
        provider, _, model = spec.partition(":")
    else:
        provider, model = spec, ""
    provider = provider.strip().lower()
    model = model.strip() or _DEFAULT_MODELS.get(provider, "")
    if not provider:
        raise ValueError("AI model spec is empty")
    if not model:
        raise ValueError(
            f"unknown AI provider {spec!r}; expected one of "
            f"{sorted(_DEFAULT_MODELS)} (with optional ``:model`` suffix)"
        )
    return _ModelSpec(provider=provider, model=model)


# ── Provider clients ─────────────────────────────────────────────


class AnthropicClient:
    """Anthropic Messages API via the official SDK (lazy-imported)."""

    name: str

    def __init__(self, model: str) -> None:
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:
            raise AIDependencyError(
                "Anthropic provider requires the ``anthropic`` SDK. "
                "Install with ``pip install pipeline-check[ai-anthropic]`` "
                "(or ``pip install anthropic``)."
            ) from exc
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise AIAuthError(
                "Anthropic provider requires the ``ANTHROPIC_API_KEY`` "
                "environment variable."
            )
        self._model = model
        self.name = f"anthropic:{model}"

    def complete(self, system: str, user: str) -> str:
        import anthropic
        client = anthropic.Anthropic()
        try:
            resp = client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as exc:
            raise AIRequestError(f"Anthropic API error: {exc}") from exc
        chunks: list[str] = []
        for block in resp.content:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                chunks.append(text)
        return "".join(chunks).strip()


class OpenAIClient:
    """OpenAI Chat Completions via the official SDK (lazy-imported)."""

    name: str

    def __init__(self, model: str) -> None:
        try:
            import openai  # noqa: F401
        except ImportError as exc:
            raise AIDependencyError(
                "OpenAI provider requires the ``openai`` SDK. "
                "Install with ``pip install pipeline-check[ai-openai]`` "
                "(or ``pip install openai``)."
            ) from exc
        if not os.environ.get("OPENAI_API_KEY"):
            raise AIAuthError(
                "OpenAI provider requires the ``OPENAI_API_KEY`` "
                "environment variable."
            )
        self._model = model
        self.name = f"openai:{model}"

    def complete(self, system: str, user: str) -> str:
        import openai
        client = openai.OpenAI()
        try:
            resp = client.chat.completions.create(
                model=self._model,
                max_tokens=2048,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
        except openai.OpenAIError as exc:
            raise AIRequestError(f"OpenAI API error: {exc}") from exc
        if not resp.choices:
            raise AIRequestError("OpenAI returned no choices")
        return (resp.choices[0].message.content or "").strip()


class OllamaClient:
    """Local Ollama via ``/api/chat``. Stdlib-only — no extra deps.

    Honors ``OLLAMA_HOST`` (defaults to ``http://localhost:11434``).
    Useful when the operator wants AI augmentation without sending
    code excerpts to a hosted provider.
    """

    name: str

    def __init__(self, model: str) -> None:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self._host = host.rstrip("/")
        self._model = model
        self.name = f"ollama:{model}"

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
                payload = json.load(resp)
        except urllib.error.URLError as exc:
            raise AIRequestError(
                f"Ollama at {self._host!r} unreachable: {exc}. "
                f"Set ``OLLAMA_HOST`` or start a local Ollama daemon."
            ) from exc
        msg = payload.get("message") if isinstance(payload, dict) else None
        if isinstance(msg, dict):
            content = msg.get("content")
            if isinstance(content, str):
                return content.strip()
        raise AIRequestError(
            f"Ollama returned an unexpected response shape: {payload!r:.200}"
        )


_PROVIDER_CTORS: dict[str, Callable[[str], AIClient]] = {
    "anthropic": AnthropicClient,
    "openai": OpenAIClient,
    "ollama": OllamaClient,
}


def select_client(spec: str) -> AIClient:
    """Resolve a ``provider[:model]`` spec to a ready-to-use client.

    Raises :class:`ValueError` for an unknown provider,
    :class:`AIDependencyError` if the SDK isn't installed, and
    :class:`AIAuthError` if the credentials are missing.
    """
    parsed = _parse_spec(spec)
    ctor = _PROVIDER_CTORS.get(parsed.provider)
    if ctor is None:
        raise ValueError(
            f"unknown AI provider {parsed.provider!r}; expected one of "
            f"{sorted(_PROVIDER_CTORS)}"
        )
    return ctor(parsed.model)


# ── Prompt construction ─────────────────────────────────────────


SYSTEM_PROMPT = (
    "You are a CI/CD security advisor. A developer is running "
    "pipeline-check (a static analyzer for CI/CD configs) and "
    "wants concrete remediation guidance grounded in their actual "
    "project.\n\n"
    "Rules of engagement:\n"
    "- Be specific to the codebase shown to you. Do NOT invent "
    "file paths or line numbers. If you don't see a path in the "
    "provided context, don't guess one.\n"
    "- If you cannot ground a recommendation in the context, say "
    "so explicitly. Generic advice is fine; pretending it's "
    "project-specific is not.\n"
    "- Keep the response under ~300 words.\n"
    "- Don't repeat the rule's title back; assume the developer "
    "already saw it.\n\n"
    "Output format:\n"
    "1. **Why this fires here** - 1-2 sentences.\n"
    "2. **Fix** - concrete code or config change. Include the "
    "file path if grounded.\n"
    "3. **False-positive risk** - 1 sentence assessment for this "
    "specific project.\n"
)


def build_user_prompt(
    rule: Rule,
    *,
    project_summary: str = "",
    file_excerpt: str | None = None,
    file_path: str | None = None,
) -> str:
    """Compose the per-rule user prompt.

    The deterministic content (rule metadata, recommendation,
    known-FP modes, CWE) frames the rule; the project-specific
    content (README excerpt, optional offending file) grounds the
    response.
    """
    parts: list[str] = []
    parts.append(f"Rule: {rule.id} - {rule.title}")
    parts.append(f"Severity: {rule.severity.value}")
    if rule.docs_note:
        parts.append(f"\nWhat it checks:\n{rule.docs_note.strip()}")
    if rule.recommendation:
        parts.append(f"\nGeneric recommendation:\n{rule.recommendation.strip()}")
    if rule.known_fp:
        parts.append("\nKnown false-positive modes:")
        for mode in rule.known_fp:
            parts.append(f"- {mode.strip()}")
    if rule.cwe:
        parts.append(f"\nCWE: {', '.join(rule.cwe)}")

    if project_summary:
        parts.append(
            f"\nProject context (README excerpt):\n{project_summary.strip()}"
        )

    if file_excerpt:
        label = file_path or "(unspecified file)"
        parts.append(
            f"\nOffending content from `{label}`:\n```\n"
            f"{file_excerpt.strip()}\n```"
        )
    else:
        parts.append(
            "\n(No offending file provided. Give a generally-applicable "
            "remediation grounded in the project context above.)"
        )

    parts.append("\nGive concrete remediation guidance now.")
    return "\n".join(parts)


# ── Project-context discovery ───────────────────────────────────


def read_readme(repo_path: str = ".", limit_lines: int = 60) -> str:
    """Read the first ``limit_lines`` of ``README.*`` if present.

    Looks for a few well-known names. Returns the empty string when
    no README is reachable; the caller can detect that and fall back
    to a generic prompt.
    """
    for name in ("README.md", "README.rst", "README.txt", "README"):
        path = os.path.join(repo_path, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                lines: list[str] = []
                for i, line in enumerate(fh):
                    if i >= limit_lines:
                        break
                    lines.append(line.rstrip())
            return "\n".join(lines)
        except (OSError, UnicodeDecodeError):
            continue
    return ""


def read_file_excerpt(path: str, limit_lines: int = 200) -> str:
    """Read up to ``limit_lines`` from ``path``. Empty string on error."""
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            head: list[str] = []
            for i, line in enumerate(fh):
                if i >= limit_lines:
                    break
                head.append(line)
        return "".join(head)
    except (OSError, UnicodeDecodeError):
        return ""


# ── Public entry point ──────────────────────────────────────────


def explain_check(
    rule: Rule,
    *,
    client: AIClient,
    repo_path: str = ".",
    context_file: str | None = None,
) -> str:
    """Return the AI-generated explanation text for *rule*.

    The caller frames the output (header, banner, footer); this
    function returns the bare model response so callers can choose
    where to place it. Raises :class:`AIRequestError` on a failure
    that the operator should see.
    """
    project_summary = read_readme(repo_path)
    file_excerpt = read_file_excerpt(context_file) if context_file else ""
    user_prompt = build_user_prompt(
        rule,
        project_summary=project_summary,
        file_excerpt=file_excerpt or None,
        file_path=context_file,
    )
    return client.complete(SYSTEM_PROMPT, user_prompt)


def render_section(client_name: str, body: str) -> str:
    """Frame the AI response with the AI-generated banner.

    Output goes through this helper (rather than being printed
    directly by the caller) so the "this section is non-deterministic"
    contract is centralised. A reader pasting the response into a
    PR comment sees the banner; a future change to that contract
    happens in one place.
    """
    body = body.strip() or "(model returned an empty response)"
    return (
        "[AI-generated, non-deterministic. Provider: "
        f"{client_name}. Treat as a triage aid, not as audit "
        "output.]\n\n"
        f"{body}\n"
    )


# ── Default-provider resolution ──────────────────────────────────


def default_spec_from_env() -> str | None:
    """Pick a sensible default provider based on env vars present.

    Order: explicit ``$PIPELINE_CHECK_AI_MODEL`` wins. Otherwise
    pick the first provider whose key is set, falling back to
    ``ollama`` if a daemon-shaped ``$OLLAMA_HOST`` is present.
    Returns ``None`` when no plausible default can be chosen — the
    caller should surface that as a usage error.
    """
    explicit = os.environ.get("PIPELINE_CHECK_AI_MODEL")
    if explicit:
        return explicit
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    return None


__all__ = [
    "AIAuthError",
    "AIClient",
    "AIDependencyError",
    "AIRequestError",
    "AnthropicClient",
    "OllamaClient",
    "OpenAIClient",
    "build_user_prompt",
    "default_spec_from_env",
    "explain_check",
    "read_file_excerpt",
    "read_readme",
    "render_section",
    "select_client",
    "SYSTEM_PROMPT",
]
