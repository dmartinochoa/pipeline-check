"""Per-pipeline taint graph for the Buildkite dataflow rules.

The Buildkite analogue of the GHA / GitLab engines. Generalises
``BK-003``'s single-step interpolation detection to a pipeline-
wide reachability problem that follows the canonical Buildkite
cross-step channel: ``buildkite-agent meta-data set / get``.

Buildkite's meta-data mechanism is the direct equivalent of
GitHub Actions' ``$GITHUB_OUTPUT`` and GitLab's
``artifacts.reports.dotenv``: a producer step writes a key /
value pair via ``buildkite-agent meta-data set``, and any
downstream step can read it via ``buildkite-agent meta-data
get``. The injection shape:

  steps:
    - label: extract
      command: |
        buildkite-agent meta-data set "title" \
            "$BUILDKITE_PULL_REQUEST_TITLE"
    - wait
    - label: use
      command: |
        TITLE=$(buildkite-agent meta-data get title)
        echo $TITLE                  # <- taint exits here

BK-003 catches the inner ``$BUILDKITE_PULL_REQUEST_TITLE``
interpolation in the producer's command. What it doesn't catch
is the consumer: ``$TITLE`` looks like any other shell variable
until you trace the meta-data round-trip. The engine here closes
that gap.

v1 limitations:

  * Buildkite meta-data is per-build, not per-step; any step
    can read what any earlier step wrote regardless of
    ``depends_on:``. We don't model temporal ordering and fire
    when both the producer and consumer pattern exist in the
    same pipeline file with a matching key.
  * ``buildkite-agent meta-data exists`` (returns 0/1) and the
    less-common ``--default`` form aren't tracked yet.
  * Plugins that provide their own meta-data abstraction
    (``cattle-ops/github-merged-pr-buildkite-plugin``, etc.)
    aren't introspected; the rule only fires on the canonical
    CLI invocations.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .base import iter_command_steps, step_commands, step_label
from .rules.bk003_untrusted_interpolation import _TAINTED_VARS


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One untrusted-input expression detected in the pipeline."""

    expr: str
    location: str


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A computed source-to-sink path through the Buildkite pipeline."""

    source: TaintSource
    hops: tuple[str, ...]
    sink_location: str
    sink_consumer: str

    def render(self) -> str:
        """One-line ``source -> hop -> ... -> sink`` rendering."""
        chain: list[str] = [
            f"${self.source.expr}@{self.source.location}",
        ]
        chain.extend(self.hops)
        chain.append(f"sink@{self.sink_location}({self.sink_consumer})")
        return " -> ".join(chain)


# ── Meta-data set / get detectors ─────────────────────────────────


# ``buildkite-agent meta-data set <key> <value>``. The CLI accepts
# the key + value as separate positional args; quoting is the
# user's responsibility. Capture both raw, the producer pass
# classifies the value separately for taint sources.
_META_SET_RE = re.compile(
    r"""
    buildkite-agent\s+meta-data\s+set\s+
    (?P<keyq>["']?)(?P<key>[A-Za-z_][\w.-]*)(?P=keyq)
    \s+
    (?P<val>(?:
        "[^"]*"
        | '[^']*'
        | \S+
    ))
    """,
    re.VERBOSE,
)

# ``buildkite-agent meta-data get <key>``. The output goes to
# stdout; the typical capture shape is ``VAR=$(... get key)``.
_META_GET_RE = re.compile(
    r"""
    buildkite-agent\s+meta-data\s+get\s+
    (?P<keyq>["']?)(?P<key>[A-Za-z_][\w.-]*)(?P=keyq)
    """,
    re.VERBOSE,
)

# Pre-compiled tainted-variable pattern. Mirrors BK-003 so the
# vocabulary stays canonical.
_TAINTED_VAR_RE = re.compile(
    r"\$\{?(?P<name>"
    + "|".join(_TAINTED_VARS)
    + r")\}?(?![A-Za-z0-9_])"
)


def _extract_meta_set(
    command: str,
) -> Iterator[tuple[str, str]]:
    """Yield ``(key, raw_value)`` for each meta-data set call in *command*."""
    for m in _META_SET_RE.finditer(command):
        yield m.group("key"), m.group("val")


def _extract_meta_get_keys(command: str) -> Iterator[str]:
    """Yield ``key`` for each meta-data get call in *command*."""
    for m in _META_GET_RE.finditer(command):
        yield m.group("key")


# ── Engine state ──────────────────────────────────────────────────


@dataclass
class _GraphState:
    """Per-pipeline taint graph.

    Tracks every meta-data key a producer step writes with
    untrusted content. Multiple steps can leak the same key;
    consumers fire once per producer-consumer pair.
    """

    # ``key -> [(producer_label, sources)]``
    leaks: dict[str, list[tuple[str, list[TaintSource]]]] = field(
        default_factory=dict,
    )

    def record_leak(
        self,
        key: str,
        producer: str,
        sources: list[TaintSource],
    ) -> None:
        bucket = self.leaks.setdefault(key, [])
        bucket.append((producer, list(sources)))

    def producers_of(self, key: str) -> list[tuple[str, list[TaintSource]]]:
        return list(self.leaks.get(key, []))


# ── Public API ────────────────────────────────────────────────────


def analyze_pipeline(doc: dict[str, Any]) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    Two passes:

      1. **Producer pass** — walk every command step. For each
         ``buildkite-agent meta-data set "K" "V"`` invocation,
         classify ``V`` against the tainted-var vocabulary
         (``BUILDKITE_PULL_REQUEST_*`` / ``BUILDKITE_MESSAGE`` /
         ``BUILDKITE_BUILD_AUTHOR*`` / branch / tag / commit
         identifiers BK-003 already flags). Recorded leaks are
         keyed by meta-data key.
      2. **Consumer pass** — walk every command step. For each
         ``buildkite-agent meta-data get K`` invocation, if pass 1
         recorded a leak under ``K``, emit a path. Same key in
         multiple producers + multiple consumers emits one path
         per cross-product cell.
    """
    if not isinstance(doc, dict):
        return []

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Pass 1: producers. ────────────────────────────────────
    for idx, step in iter_command_steps(doc):
        label = step_label(step, idx)
        for cmd in step_commands(step):
            for key, raw_val in _extract_meta_set(cmd):
                sources: list[TaintSource] = []
                for m in _TAINTED_VAR_RE.finditer(raw_val):
                    sources.append(TaintSource(
                        expr=m.group("name"),
                        location=f"{label}",
                    ))
                if sources:
                    state.record_leak(key, label, sources)

    # ── Pass 2: consumers. ────────────────────────────────────
    for idx, step in iter_command_steps(doc):
        consumer_label = step_label(step, idx)
        for cmd in step_commands(step):
            for key in _extract_meta_get_keys(cmd):
                producers = state.producers_of(key)
                if not producers:
                    continue
                for producer_label, sources in producers:
                    if producer_label == consumer_label:
                        # Same step writes-then-reads its own key.
                        # That's BK-003 territory (direct interpolation
                        # within the step), skip cross-step emission.
                        continue
                    for src in sources:
                        paths.append(TaintPath(
                            source=src,
                            hops=(
                                f"steps.{producer_label}."
                                f"meta-data.{key}",
                            ),
                            sink_location=consumer_label,
                            sink_consumer=(
                                f"buildkite-agent meta-data get {key}"
                            ),
                        ))
    return paths


__all__ = [
    "TaintPath",
    "TaintSource",
    "analyze_pipeline",
]
