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
- ``GHA-008`` / ``GL-008`` / ``BB-008`` / ``ADO-008`` — redact
  credential-shaped literals embedded in the workflow by replacing the
  value with ``\"<REDACTED>\"`` and leaving a ``# TODO:`` comment.
- ``JF-008`` — Groovy-syntax variant of the secret redactor.
- ``GHA-015`` — insert ``timeout-minutes: 30`` into GitHub Actions jobs.
- ``GL-015`` — insert ``timeout: 30 minutes`` into GitLab CI jobs.
- ``ADO-015`` — insert ``timeoutInMinutes: 30`` into Azure DevOps jobs
  (only flat ``jobs:`` blocks; skips ``stages:`` → ``jobs:`` nesting).
- ``GHA-016`` / ``GL-016`` / ``ADO-016`` / ``BB-012`` / ``JF-016`` —
  comment out ``curl | bash`` / ``wget | sh`` lines with a TODO marker.
- ``GHA-017`` / ``GL-017`` / ``ADO-017`` / ``BB-013`` / ``JF-017`` —
  strip ``--privileged``, ``--cap-add``, ``--net=host``, and host-mount
  ``-v`` flags from ``docker run`` commands.
- ``GHA-018`` / ``GL-018`` / ``ADO-018`` / ``BB-014`` / ``JF-018`` —
  strip ``--index-url http://``, ``--registry http://``,
  ``--trusted-host``, and ``--no-verify`` from package-install commands.

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


@register("GHA-015")
def _fix_gha015(content: str, finding: Finding) -> str | None:
    """Insert ``timeout-minutes: 30`` into jobs that lack one.

    Scans for job-level keys under ``jobs:`` and inserts the timeout
    as the first property of each job that doesn't already have one.
    Idempotent: skips jobs that already declare ``timeout-minutes``.
    """
    lines = content.splitlines(keepends=True)
    in_jobs = False
    job_indent: str | None = None  # indent string of job-level keys
    result: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # Detect `jobs:` top-level key.
        if re.match(r"^jobs\s*:", stripped):
            in_jobs = True
            job_indent = None  # reset — will be learned from first child
            result.append(line)
            i += 1
            continue
        # Detect another top-level key (exits jobs block).
        if in_jobs and re.match(r"^\S", stripped) and not stripped.startswith("#"):
            in_jobs = False
        if in_jobs and stripped and not stripped.startswith("#"):
            # Learn the job indent from the first non-blank, non-comment
            # line under `jobs:`.
            leading = len(line) - len(line.lstrip())
            if job_indent is None and leading > 0:
                job_indent = " " * leading
            # Only match keys at exactly the job indent level.
            if (
                job_indent is not None
                and line.startswith(job_indent)
                and leading == len(job_indent)
                and re.match(r"\w[\w-]*:\s*$", line.lstrip())
            ):
                child_indent = job_indent + "  "
                result.append(line)
                i += 1
                # Scan ahead to check if timeout-minutes already exists.
                has_timeout = False
                j = i
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.rstrip()
                    if next_stripped and not next_stripped.startswith("#"):
                        next_indent = len(next_line) - len(next_line.lstrip())
                        if next_indent <= len(job_indent):
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


# ── GitLab / Azure timeout fixers ──────────────────────────────────────
#
# GitLab and Azure use the same top-level-job pattern as GitHub but with
# different timeout key names.  Rather than duplicate the scan logic we
# share a generic helper that takes the keyword and the value string.


def _fix_yaml_timeout(
    content: str, keyword: str, value: str, top_key: str | None = None,
) -> str | None:
    """Insert *keyword*: *value* into every top-level job missing it.

    *top_key* is an optional ``jobs:`` equivalent (Azure uses it);
    GitLab jobs live at the root alongside non-job keys, so *top_key*
    is ``None`` for that provider — we treat every root-level mapping
    key that isn't a known GitLab meta key as a job.
    """
    _GL_META = {
        "default", "include", "stages", "variables", "workflow",
        "image", "services", "cache", "before_script", "after_script",
        "pages",
    }
    lines = content.splitlines(keepends=True)
    result: list[str] = []
    changed = False
    i = 0

    if top_key is not None:
        # ── Azure-style: jobs live under a top-level key ──────────
        in_block = False
        job_indent: str | None = None
        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()
            if re.match(re.escape(top_key) + r"\s*:", stripped) and not line[0].isspace():
                in_block = True
                job_indent = None
                result.append(line)
                i += 1
                continue
            if in_block and stripped and not stripped.startswith("#") and not line[0].isspace():
                in_block = False
            if in_block and stripped and not stripped.startswith("#"):
                leading = len(line) - len(line.lstrip())
                if job_indent is None and leading > 0:
                    job_indent = " " * leading
                if (
                    job_indent is not None
                    and leading == len(job_indent)
                    and re.match(r"\w[\w-]*:\s*$", line.lstrip())
                ):
                    child_indent = job_indent + "  "
                    result.append(line)
                    i += 1
                    has_kw = _scan_for_key(lines, i, keyword, len(job_indent))
                    if not has_kw:
                        result.append(f"{child_indent}{keyword}: {value}\n")
                        changed = True
                    continue
            result.append(line)
            i += 1
    else:
        # ── GitLab-style: jobs are root-level keys ────────────────
        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()
            if (
                stripped
                and not stripped.startswith("#")
                and not line[0].isspace()
                and re.match(r"[\w][\w-]*:\s*$", stripped)
                and stripped.split(":")[0] not in _GL_META
            ):
                child_indent = "  "
                result.append(line)
                i += 1
                has_kw = _scan_for_key(lines, i, keyword, 0)
                if not has_kw:
                    result.append(f"{child_indent}{keyword}: {value}\n")
                    changed = True
                continue
            result.append(line)
            i += 1

    if not changed:
        return None
    return "".join(result)


def _scan_for_key(
    lines: list[str], start: int, keyword: str, parent_indent: int,
) -> bool:
    """Return True if *keyword* appears inside the block starting at *start*."""
    j = start
    while j < len(lines):
        ln = lines[j]
        s = ln.rstrip()
        if s and not s.startswith("#"):
            ind = len(ln) - len(ln.lstrip())
            if ind <= parent_indent:
                break
        if keyword in ln:
            return True
        j += 1
    return False


@register("GL-015")
def _fix_gl015(content: str, finding: Finding) -> str | None:
    return _fix_yaml_timeout(content, "timeout", "30 minutes")


@register("ADO-015")
def _fix_ado015(content: str, finding: Finding) -> str | None:
    """Insert ``timeoutInMinutes: 30`` into Azure ``- job:`` list items.

    Azure jobs are YAML list items (``- job: Name``), not mapping keys.
    """
    _JOB_ITEM_RE = re.compile(r"^(\s*)- job:\s*\S+")
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _JOB_ITEM_RE.match(line)
        if m:
            base_indent = m.group(1)
            # Properties of this job item are at base_indent + 2 spaces
            child_indent = base_indent + "  "
            out.append(line)
            i += 1
            has_kw = _scan_for_key(lines, i, "timeoutInMinutes", len(base_indent))
            if not has_kw:
                out.append(f"{child_indent}timeoutInMinutes: 30\n")
                changed = True
            continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── Curl-pipe comment-out ──────────────────────────────────────────────

_CURL_PIPE_LINE_RE = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b"
    r"|(?:curl|wget)\s+[^\n|]*\|\s*(?:python|perl|ruby)\b",
)

_TODO_CURL = "TODO(pipelineguard): download, verify checksum, then execute"


def _comment_curl_pipe(content: str, finding: Finding) -> str | None:
    """Comment out curl-pipe / wget-pipe lines across all providers."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        # Skip lines that are already comments or already have our marker.
        if _TODO_CURL in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if _CURL_PIPE_LINE_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            comment_char = "#"
            out.append(f"{indent}{comment_char} {_TODO_CURL}\n")
            out.append(f"{indent}{comment_char} {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-016", "GL-016", "ADO-016", "BB-012", "JF-016"):
    register(_cid)(_comment_curl_pipe)


# ── Docker --privileged removal ────────────────────────────────────────

_DOCKER_FLAG_RE = re.compile(
    r"\s+--privileged(?=\s|$)"
    r"|\s+--cap-add\s+\S+"
    r"|\s+--net[= ]host"
    r"|\s+-v\s+/[^:\s]*:/\S*",
)


def _strip_docker_flags(content: str, finding: Finding) -> str | None:
    """Strip --privileged, --cap-add, --net=host, -v /host:/ from docker run."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if "docker" in line and _DOCKER_FLAG_RE.search(line):
            new_line = _DOCKER_FLAG_RE.sub("", line)
            # Collapse multiple spaces left by removals.
            new_line = re.sub(r"  +", " ", new_line)
            if new_line != line:
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-017", "GL-017", "ADO-017", "BB-013", "JF-017"):
    register(_cid)(_strip_docker_flags)


# ── Insecure package-install flag removal ──────────────────────────────

_PKG_UNSAFE_FLAG_RE = re.compile(
    r"\s+--index-url\s+http://\S+"
    r"|\s+--extra-index-url\s+http://\S+"
    r"|\s+--trusted-host\s+\S+"
    r"|\s+--registry[= ]http://\S+"
    r"|\s+--no-verify"
)


def _strip_pkg_flags(content: str, finding: Finding) -> str | None:
    """Remove insecure registry / trust-override flags from package install."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _PKG_UNSAFE_FLAG_RE.search(line):
            new_line = _PKG_UNSAFE_FLAG_RE.sub("", line)
            new_line = re.sub(r"  +", " ", new_line)
            if new_line != line:
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-018", "GL-018", "ADO-018", "BB-014", "JF-018"):
    register(_cid)(_strip_pkg_flags)


# ── Jenkins secret redaction (Groovy syntax) ───────────────────────────


@register("JF-008")
def _fix_jf008(content: str, finding: Finding) -> str | None:
    """Redact credential-shaped literals in Groovy source.

    Handles ``VAR = "AKIA..."`` and ``def x = "ghp_..."`` patterns.
    """
    from .checks._patterns import SECRET_VALUE_RE

    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if "<REDACTED>" in line:
            out.append(line)
            continue
        # Groovy assignments: VAR = "value" or def var = "value"
        m = re.match(
            r'^(\s*(?:def\s+)?[\w.]+\s*=\s*)["\']([^"\']+)["\'](.*)$',
            line,
        )
        if m:
            prefix, value, rest = m.groups()
            if SECRET_VALUE_RE.fullmatch(value) or value.startswith("AKIA"):
                todo = "// TODO(pipelineguard): rotate and wire up a credential"
                new_line = f'{prefix}"<REDACTED>"  {todo}\n'
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


# ── BB-005 Bitbucket timeout fixer ───────────────────────────────────


@register("BB-005")
def _fix_bb005(content: str, finding: Finding) -> str | None:
    """Insert ``max-time: 120`` into Bitbucket steps missing it.

    Bitbucket steps are list items under ``- step:``. Scans for
    ``- step:`` markers and checks whether the step's child block
    already declares ``max-time:``.
    """
    _STEP_RE = re.compile(r"^(\s*)- step:\s*$")
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _STEP_RE.match(line)
        if m:
            base_indent = m.group(1)
            child_indent = base_indent + "    "  # step children are 4 spaces in
            out.append(line)
            i += 1
            has_timeout = _scan_for_key(lines, i, "max-time", len(base_indent))
            if not has_timeout:
                out.append(f"{child_indent}max-time: 120\n")
                changed = True
            continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── JF-015 Jenkins timeout fixer ─────────────────────────────────────


@register("JF-015")
def _fix_jf015(content: str, finding: Finding) -> str | None:
    """Insert a TODO comment for adding a timeout wrapper.

    Jenkins timeout is Groovy syntax ``timeout(time: N, unit: 'MINUTES')``
    which can't be safely inserted by a text fixer, so we add a comment.
    """
    marker = "// TODO(pipelineguard): wrap with timeout(time: 30, unit: 'MINUTES')"
    if marker in content:
        return None
    # Find `pipeline {` and insert after it.
    m = re.search(r"^(\s*)pipeline\s*\{", content, re.MULTILINE)
    if m is None:
        return None
    insert_at = m.end()
    indent = m.group(1) + "    "
    return content[:insert_at] + f"\n{indent}{marker}" + content[insert_at:]


# ── Pinning TODO comments ────────────────────────────────────────────

_TODO_PIN = "TODO(pipelineguard): pin to commit SHA"
_TODO_PIN_IMG = "TODO(pipelineguard): pin to digest"


@register("GHA-001")
def _fix_gha001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned action uses: references."""
    _USES_RE = re.compile(r"^(\s*-?\s*uses:\s*)(\S+@)([^#\s]+)(.*)$")
    _SHA_RE = re.compile(r"^[0-9a-f]{40}$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _USES_RE.match(line.rstrip("\n"))
        if m:
            prefix, action, ref, rest = m.groups()
            if not _SHA_RE.match(ref):
                new_line = f"{prefix}{action}{ref}{rest}  # {_TODO_PIN}\n"
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("GL-001")
def _fix_gl001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned image: references."""
    _IMAGE_RE = re.compile(r"^(\s*image:\s*)(\S+)(.*)$")
    _DIGEST_RE = re.compile(r"@sha256:")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN_IMG in line:
            out.append(line)
            continue
        m = _IMAGE_RE.match(line.rstrip("\n"))
        if m:
            prefix, image, rest = m.groups()
            if not _DIGEST_RE.search(image):
                new_line = f"{prefix}{image}{rest}  # {_TODO_PIN_IMG}\n"
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("BB-001")
def _fix_bb001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned pipe: references."""
    _PIPE_RE = re.compile(r"^(\s*(?:- )?pipe:\s*)(\S+)(.*)$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _PIPE_RE.match(line.rstrip("\n"))
        if m:
            new_line = f"{line.rstrip()}  # {_TODO_PIN}\n"
            out.append(new_line)
            changed = True
            continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("ADO-001")
def _fix_ado001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned task: references."""
    _TASK_RE = re.compile(r"^(\s*-?\s*task:\s*)(\S+@\S+)(.*)$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _TASK_RE.match(line.rstrip("\n"))
        if m:
            new_line = f"{line.rstrip()}  # {_TODO_PIN}\n"
            out.append(new_line)
            changed = True
            continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


# ── Token persistence comment-out ────────────────────────────────────

_TODO_TOKEN = "WARNING(pipelineguard): token written to persistent storage — remove this line"


def _comment_token_persist(content: str, finding: Finding) -> str | None:
    """Comment out lines that persist tokens to files/env."""
    from .checks.bitbucket.rules.bb017_token_persistence import _TOKEN_PERSIST_RE as BB_RE
    from .checks.github.rules.gha019_token_persistence import _TOKEN_PERSIST_RE as GHA_RE
    from .checks.gitlab.rules.gl020_token_persistence import _TOKEN_PERSIST_RE as GL_RE

    persist_re = {"GHA-019": GHA_RE, "GL-020": GL_RE, "BB-017": BB_RE}
    pattern = persist_re.get(finding.check_id.upper())
    if pattern is None:
        return None

    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_TOKEN in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if pattern.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_TOKEN}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-019", "GL-020", "BB-017"):
    register(_cid)(_comment_token_persist)


# ── Deploy environment stubs ─────────────────────────────────────────

_TODO_ENV = "TODO(pipelineguard): configure deployment environment"
_DEPLOY_NAME_RE = re.compile(r"(?i)(deploy|release|publish|promote)")


@register("GHA-014")
def _fix_gha014(content: str, finding: Finding) -> str | None:
    """Insert ``environment:`` placeholder into deploy-named GHA jobs."""
    lines = content.splitlines(keepends=True)
    in_jobs = False
    job_indent: str | None = None
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if re.match(r"^jobs\s*:", stripped):
            in_jobs = True
            job_indent = None
            out.append(line)
            i += 1
            continue
        if in_jobs and re.match(r"^\S", stripped) and not stripped.startswith("#"):
            in_jobs = False
        if in_jobs and stripped and not stripped.startswith("#"):
            leading = len(line) - len(line.lstrip())
            if job_indent is None and leading > 0:
                job_indent = " " * leading
            if (
                job_indent is not None
                and leading == len(job_indent)
                and re.match(r"\w[\w-]*:\s*$", line.lstrip())
            ):
                job_name = line.lstrip().split(":")[0]
                child_indent = job_indent + "  "
                out.append(line)
                i += 1
                if _DEPLOY_NAME_RE.search(job_name):
                    has_env = _scan_for_key(lines, i, "environment", len(job_indent))
                    if not has_env:
                        out.append(f"{child_indent}environment: # {_TODO_ENV}\n")
                        changed = True
                continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── *-021 npm install → npm ci ───────────────────────────────────────

_NPM_INSTALL_RE = re.compile(r"\bnpm\s+install\b")


def _fix_npm_ci(content: str, finding: Finding) -> str | None:
    """Replace bare ``npm install`` with ``npm ci``."""
    if "npm ci" in content and "npm install" not in content:
        return None
    out = _NPM_INSTALL_RE.sub("npm ci", content)
    if out == content:
        return None
    return out


for _cid in ("GHA-021", "GL-021", "ADO-021", "BB-021", "JF-021"):
    register(_cid)(_fix_npm_ci)


# ── *-022 dependency-update command comment-out ──────────────────────

_TODO_DEP_UPDATE = "TODO(pipelineguard): remove dependency update command; use lockfile-pinned install"


def _comment_dep_update(content: str, finding: Finding) -> str | None:
    """Comment out dependency-update commands."""
    from .checks.base import _DEP_UPDATE_TOOL_EXEMPT_RE, DEP_UPDATE_RE
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_DEP_UPDATE in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if DEP_UPDATE_RE.search(line) and not _DEP_UPDATE_TOOL_EXEMPT_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_DEP_UPDATE}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-022", "GL-022", "ADO-022", "BB-022", "JF-022"):
    register(_cid)(_comment_dep_update)


# ── *-023 TLS bypass comment-out ─────────────────────────────────────

_TODO_TLS = "TODO(pipelineguard): remove TLS/SSL verification bypass"


def _comment_tls_bypass(content: str, finding: Finding) -> str | None:
    """Comment out TLS verification bypass lines."""
    from .checks.base import TLS_BYPASS_RE
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_TLS in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if TLS_BYPASS_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_TLS}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-023", "GL-023", "ADO-023", "BB-023", "JF-023"):
    register(_cid)(_comment_tls_bypass)
