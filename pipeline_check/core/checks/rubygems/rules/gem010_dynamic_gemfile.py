"""GEM-010. Gemfile uses dynamic gem-list resolution (eval / Dir.glob / require_relative)."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-010",
    title="Gemfile uses dynamic gem-list resolution",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Inline the dynamic ``gem`` declarations into the "
        "Gemfile directly. Bundler accepts arbitrary Ruby "
        "code at parse time, which is convenient (one Gemfile "
        "for many environments) but defeats every static "
        "audit you might run against the manifest: the rule "
        "pack here, ``bundler-audit``, ``dependabot``, and "
        "every other consumer that walks the Gemfile as data "
        "sees a hole where the dynamic block expanded into. "
        "If the dynamism is genuinely needed, gate it behind "
        "``group :development`` so production / CI Gemfiles "
        "stay static, or pre-expand the dynamic block into a "
        "generated static file and commit that."
    ),
    docs_note=(
        "Fires when the Gemfile body contains any of "
        "``Dir.glob`` / ``Dir[``, ``eval``, ``instance_eval``, "
        "``require_relative``, ``load ``, or "
        "``File.read`` calls at file scope. Lines inside "
        "comments (``#`` prefix) are ignored. The match is "
        "conservative — a Gemfile that uses ``ENV[\"RAILS_ENV\"]`` "
        "in an ``if`` block doesn't trip the rule; the rule "
        "only fires on code paths that *resolve gem names from "
        "elsewhere*."
    ),
    known_fp=(
        "Some monorepo / engine layouts intentionally split "
        "their Gemfiles via ``eval_gemfile`` (the documented "
        "Bundler shorthand for static inclusion). The rule "
        "treats ``eval_gemfile \"<literal>\"`` as a "
        "static-inclusion form and passes; only ``eval(...)`` "
        "with non-literal arguments and the ``Dir.glob`` / "
        "``require_relative`` shapes are flagged. If the "
        "dynamic resolution is unavoidable, suppress with a "
        "one-line rationale naming the static-generation "
        "workflow.",
    ),
    incident_refs=(
        "A Gemfile that runs ``eval File.read(\"#{ENV[...]}\")`` "
        "or globbs ``Dir[\"vendor/*/Gemfile\"].each { |f| "
        "eval_gemfile f }`` is unauditable by any static "
        "tool. The supply-chain risk is two-step: the file "
        "the eval reads becomes a manifest-level injection "
        "point that the manifest review process never "
        "covered.",
    ),
    exploit_example=(
        "# Vulnerable: dynamic gem resolution.\n"
        "source 'https://rubygems.org'\n"
        "Dir.glob('plugins/*/Gemfile').each do |f|\n"
        "  eval_gemfile f\n"
        "end\n"
        "# What gems land in the bundle? Nobody knows without\n"
        "# running the resolver. A new file in plugins/ silently\n"
        "# changes the dep graph.\n"
        "\n"
        "# Safe: static includes via the documented helper.\n"
        "source 'https://rubygems.org'\n"
        "eval_gemfile 'plugins/payments/Gemfile'\n"
        "eval_gemfile 'plugins/billing/Gemfile'\n"
        "# Or inline the gems directly.\n"
        "gem 'payments-core', '1.2.3'\n"
        "gem 'billing-core', '4.5.6'"
    ),
)


# Conservative regex: dynamic call shapes at line scope.
# ``eval_gemfile "literal"`` (static include) is explicitly NOT
# matched here — we exclude it via the negative lookahead on
# ``eval_gemfile``. ``require_relative`` is matched because it
# loads code that may add ``gem`` declarations dynamically.
_DYNAMIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Dir.glob",        re.compile(r"\bDir\s*\.\s*glob\b")),
    ("Dir[\"…\"]",      re.compile(r"\bDir\s*\[")),
    ("eval(...)",       re.compile(r"\beval\s*\((?!_gemfile)")),
    ("instance_eval",   re.compile(r"\binstance_eval\b")),
    ("require_relative", re.compile(r"^\s*require_relative\b", re.MULTILINE)),
    # ``load "extra.rb"`` at line scope executes a file that may add
    # ``gem`` declarations, the same dynamic-resolution shape as
    # ``require_relative``. (A bare ``require`` merely loads a library
    # and is far too common to flag, so it isn't matched.)
    ("load",            re.compile(r"^\s*load\b", re.MULTILINE)),
    ("File.read",       re.compile(r"\bFile\s*\.\s*read\b")),
)

#: The ``ruby`` directive form that pins the interpreter version, e.g.
#: ``ruby File.read('.ruby-version').strip`` or ``ruby file: ".ruby-version"``.
_RUBY_VERSION_LINE_RE = re.compile(r"^\s*ruby\s+(?:File\s*\.\s*read\b|file:)")


def _strip_comments(line: str) -> str:
    """Drop ``# ...`` trailing comments; ``#{...}`` is interpolation
    and is preserved."""
    out: list[str] = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "#":
            if i + 1 < len(line) and line[i + 1] == "{":
                # Interpolation, keep going.
                out.append(ch)
                i += 1
                continue
            break
        out.append(ch)
        i += 1
    return "".join(out)


def check(pom: GemFile) -> Finding:
    offenders: list[tuple[str, int]] = []
    for ln, raw_line in enumerate(pom.text.splitlines(), start=1):
        body = _strip_comments(raw_line)
        if not body.strip():
            continue
        for label, pat in _DYNAMIC_PATTERNS:
            if not pat.search(body):
                continue
            # ``ruby File.read('.ruby-version').strip`` pins the Ruby
            # version, not a gem list — the single most common
            # non-dynamic ``File.read`` in a real Gemfile.
            if label == "File.read" and _RUBY_VERSION_LINE_RE.match(body):
                continue
            offenders.append((label, ln))
            break

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Gemfile uses no dynamic gem-list resolution "
                "constructs."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    rendered = ", ".join(f"{lbl}@L{ln}" for lbl, ln in offenders[:5])
    suffix = "…" if len(offenders) > 5 else ""
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"Gemfile uses {len(offenders)} dynamic-resolution "
            f"construct(s): {rendered}{suffix}. Inline the "
            f"affected gem declarations or use the static "
            f"``eval_gemfile \"<literal>\"`` form so the "
            f"manifest is auditable as data."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=[Location(
            path=pom.path,
            start_line=offenders[0][1], end_line=offenders[0][1],
        )],
    )
