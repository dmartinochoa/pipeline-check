"""Suggest concrete source edits to remediate a finding.

Each fixer takes the raw YAML text of a workflow file plus the relevant
finding and returns the edited text, or ``None`` if the fixer can't
safely generate a patch (e.g. the file has already been fixed by hand,
or the issue requires data the scanner doesn't have).

Design rules:

- Fixers never touch the filesystem. ``render_patch`` converts the
  before/after pair into a unified diff; the CLI writes the patch to
  stdout and the user decides whether to apply it.
- Fixers must be *idempotent* — running one whose output is already
  present returns ``None``, never a no-op patch.
- Fixers operate on text, not the parsed YAML AST. Parsing and
  re-serialising destroys comments, blank lines, and YAML style that
  maintainers rely on; text patches preserve them.

Registered fixers:

- ``GHA-004`` — add a top-level ``permissions: contents: read`` block.
- ``GHA-002`` — add ``persist-credentials: false`` to ``actions/checkout``
  steps (defence-in-depth when pull_request_target checks out PR head).
- ``GHA-008`` — redact credential-shaped literals embedded in the
  workflow by replacing the value with ``\"<REDACTED>\"`` and leaving
  a ``# TODO:`` comment for the operator to wire up a real secret.
- ``GHA-015`` — insert ``timeout-minutes: 30`` into GitHub Actions jobs
  that lack one.

GHA-001 SHA-pinning is not included because resolving the current SHA
for a tagged action requires a network call to the GitHub API.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Callable

from .checks.base import Finding

Fixer = Callable[[str, Finding], "str | None"]

_FIXERS: dict[str, Fixer] = {}


def register(check_id: str) -> Callable[[Fixer], Fixer]:
    """Decorator used by fixers to register themselves under a check ID."""
    def _wrap(fn: Fixer) -> Fixer:
        _FIXERS[check_id.upper()] = fn
        return fn
    return _wrap


def available_fixers() -> list[str]:
    return sorted(_FIXERS.keys())


def generate_fix(finding: Finding, content: str) -> str | None:
    """Run the registered fixer for ``finding.check_id`` against ``content``.

    Returns the edited text, or ``None`` if no fixer is registered or
    the fixer decided the content already satisfies the check.

    Fixer exceptions propagate — the CLI catches at the call site so a
    single broken fixer doesn't abort a batch run, but a bug in a
    fixer surfaces instead of being silently swallowed.
    """
    fn = _FIXERS.get(finding.check_id.upper())
    if fn is None:
        return None
    out = fn(content, finding)
    if out is None or out == content:
        return None
    return out


def render_patch(path: str, before: str, after: str) -> str:
    """Unified diff between ``before`` and ``after`` for *path*."""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


# ── Fixers ────────────────────────────────────────────────────────────────


_TOPLEVEL_KEY_RE = re.compile(r"^(?:permissions|jobs|on|name|env|defaults)\s*:",
                              re.MULTILINE)

# actions/checkout step, capturing leading indent + the full action
# line so we can anchor subsequent edits relative to it.
#
# Handles two styles:
#   (1) `- uses: actions/checkout@v4`    — single-line step
#   (2) `- name: Checkout`               — step with separate name
#       `  uses: actions/checkout@v4`
#
# The indent group always captures the column the `uses:` key starts
# at, whether that's after a leading `- ` (form 1) or two spaces under
# a named step (form 2). Downstream edits use that column to compute
# the right sub-indent for the `with:` block.
_CHECKOUT_USES_RE = re.compile(
    # ``prefix`` captures everything before ``uses:`` so the step's
    # indent column can be derived regardless of form. Its length is
    # the column number ``uses:`` (and therefore ``with:``) lives at.
    r"^(?P<prefix> *(?:-\s+)?)uses:\s*actions/checkout@\S+\s*$",
    re.MULTILINE,
)


@register("GHA-004")
def _fix_gha004(content: str, finding: Finding) -> str | None:
    """Insert ``permissions: contents: read`` at the top of the workflow.

    Idempotent: returns ``None`` if a top-level ``permissions:`` key
    already exists.
    """
    for m in _TOPLEVEL_KEY_RE.finditer(content):
        if m.group(0).split(":", 1)[0] == "permissions":
            return None

    # Insert the block before the first `jobs:` (the canonical anchor)
    # or, if no jobs: exists, before the first `on:` trigger.
    anchor = re.search(r"^jobs\s*:", content, re.MULTILINE) or \
             re.search(r"^on\s*:", content, re.MULTILINE)
    if anchor is None:
        return None
    insert_at = anchor.start()
    block = "permissions:\n  contents: read\n\n"
    return content[:insert_at] + block + content[insert_at:]


@register("GHA-002")
def _fix_gha002(content: str, finding: Finding) -> str | None:
    """Add ``persist-credentials: false`` under every actions/checkout step.

    Doesn't resolve the underlying GHA-002 (pull_request_target +
    PR head) on its own — that requires a workflow redesign — but
    the checkout option is a defence-in-depth measure that reduces
    the blast radius of the issue and is always safe to apply.
    Idempotent: skips checkout steps that already set the flag.
    """
    edits: list[tuple[int, int, str]] = []
    for m in _CHECKOUT_USES_RE.finditer(content):
        # ``uses:`` lives at column len(prefix). ``with:`` is a sibling
        # (same column) and its children live at +2 more spaces.
        uses_col = " " * len(m.group("prefix"))
        child_col = uses_col + "  "
        after = content[m.end():]
        # A ``with:`` block sits right under the uses line at the same
        # column, followed by at least one child indented two spaces
        # deeper. Recognise either style of quoting for the child.
        block_match = re.match(
            r"\n" + re.escape(uses_col) + r"with:\s*\n"
            r"(?:" + re.escape(child_col) + r"\S[^\n]*\n?)+",
            after,
        )
        if block_match:
            existing_block = block_match.group(0)
            if "persist-credentials" in existing_block:
                continue
            # Append the flag to the existing with block. Ensure the
            # inserted line ends in a newline even when the matched
            # block was at EOF without one.
            insertion = f"{child_col}persist-credentials: false\n"
            insert_at = m.end() + block_match.end()
            if not content[m.end():].endswith("\n") and insert_at == len(content):
                insertion = "\n" + insertion
            edits.append((insert_at, insert_at, insertion))
        else:
            # No with: block — add one right after the uses line.
            insertion = (
                f"\n{uses_col}with:\n"
                f"{child_col}persist-credentials: false"
            )
            edits.append((m.end(), m.end(), insertion))
    if not edits:
        return None
    # Apply edits from the end backwards so earlier offsets stay valid.
    out = content
    for start, end, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[end:]
    return out


@register("GHA-008")
@register("GL-008")
@register("BB-008")
@register("ADO-008")
def _fix_gha008(content: str, finding: Finding) -> str | None:
    """Replace credential-shaped literals with ``<REDACTED>`` + TODO comment.

    A defensive edit: the scanner already flagged these as compromised
    (they're in plaintext YAML, which is forkable and logged), so
    scrubbing the value from the repo is always safe. The operator
    still needs to rotate the key and wire up a real secret — we
    leave a ``# TODO:`` comment so the change is visible in review.

    Registered for all YAML-based providers (GHA, GL, BB, ADO). The
    fixer operates on raw text, so the same logic works across all
    YAML dialects. Jenkins (JF-008) is excluded — Groovy syntax
    needs a different approach.
    """
    from .checks._patterns import SECRET_VALUE_RE
    out_lines: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        new_line = line
        # Conservative: only redact whole-token matches on the RHS of
        # a ``key: value`` pair, not inside arbitrary scripts.
        m = re.match(r"^(\s*[^#:\n]+:\s*)(\S+)(\s*)(#.*)?(\n?)$", new_line)
        if m:
            prefix, value, trailing_ws, comment, newline = m.groups()
            stripped = value.strip("\"'")
            if SECRET_VALUE_RE.fullmatch(stripped) or stripped.startswith("AKIA"):
                # Preserve the operator's existing comment (if any)
                # alongside our TODO marker — throwing it away loses
                # ticket numbers, blame context, or other hints that
                # the original author left in the file.
                todo = "# TODO(pipelineguard): rotate and wire up a secret"
                if comment:
                    original = comment.lstrip("#").strip()
                    todo = f"# {original} -- TODO(pipelineguard): rotate and wire up a secret"
                new_line = (
                    f"{prefix}\"<REDACTED>\"{trailing_ws or ''}"
                    f"  {todo}\n"
                )
                changed = True
        out_lines.append(new_line)
    if not changed:
        return None
    return "".join(out_lines)


# ── Timeout fixer ──────────────────────────────────────────────────────

# Matches a job ID line under `jobs:` in GitHub Actions.
# e.g. "  build:" with leading whitespace.
_JOB_RE = re.compile(r"^( {2,})(\w[\w-]*):\s*$", re.MULTILINE)


@register("GHA-015")
def _fix_gha015(content: str, finding: Finding) -> str | None:
    """Insert ``timeout-minutes: 30`` into jobs that lack one.

    Scans for job-level keys under ``jobs:`` and inserts the timeout
    as the first property of each job that doesn't already have one.
    Idempotent: skips jobs that already declare ``timeout-minutes``.
    """
    lines = content.splitlines(keepends=True)
    in_jobs = False
    result: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # Detect `jobs:` top-level key.
        if re.match(r"^jobs\s*:", stripped):
            in_jobs = True
            result.append(line)
            i += 1
            continue
        # Detect another top-level key (exits jobs block).
        if in_jobs and re.match(r"^\S", stripped) and not stripped.startswith("#"):
            in_jobs = False
        if in_jobs:
            m = _JOB_RE.match(line)
            if m:
                indent = m.group(1)
                child_indent = indent + "  "
                result.append(line)
                i += 1
                # Check if timeout-minutes already exists in this job.
                has_timeout = False
                j = i
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.rstrip()
                    # Another job or top-level key means we left this job.
                    if next_stripped and not next_stripped.startswith("#"):
                        # Is this at the same or lesser indent? That means a new job or key.
                        line_indent = len(next_line) - len(next_line.lstrip())
                        if line_indent <= len(indent) and next_stripped:
                            break
                    if "timeout-minutes" in next_line:
                        has_timeout = True
                        break
                    j += 1
                if not has_timeout:
                    result.append(f"{child_indent}timeout-minutes: 30\n")
                    changed = True
                continue
        result.append(line)
        i += 1
    if not changed:
        return None
    return "".join(result)
