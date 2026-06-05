"""Output formatters -- terminal (rich) and JSON."""

import json
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table

from .chains import Chain
from .checks.base import (
    Confidence,
    Finding,
    Severity,
    inline_exploit,
    severity_rank,
)
from .inventory import Component
from .report_view import failure_sort_key, report_sort_key
from .scorer import ScoreResult

#: Confidence styling for the findings table. HIGH is the default a
#: rule keeps unless it opts down to a heuristic match, so it recedes
#: (dim); MEDIUM and LOW are the ones worth a second look, so they read
#: at full weight. The column itself only renders when confidence
#: actually varies (see ``report_terminal``).
_CONFIDENCE_STYLE: dict[Confidence, str] = {
    Confidence.HIGH: "dim",
    Confidence.MEDIUM: "",
    Confidence.LOW: "italic",
}

#: Short, lowercase confidence labels for the table cell.
_CONF_LABEL: dict[Confidence, str] = {
    Confidence.HIGH: "high",
    Confidence.MEDIUM: "med",
    Confidence.LOW: "low",
}

# Bump when the JSON payload shape changes in a way consumers need to
# branch on (e.g. a new top-level key, a renamed field). Minor-revision
# adds (appending an optional field) do NOT require a version bump.
JSON_SCHEMA_VERSION = "1.1"

# Severity scale, matching the design system's terminal-tuned tokens
# (the same hues the HTML report and docs site use, brightened for
# legibility on a dark terminal background). CRITICAL red, HIGH orange,
# MEDIUM gold, LOW cyan, INFO gray. Keeping these 1:1 with the other
# surfaces is what makes a screenshot of the CLI read as the same
# product as the docs.
_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold #dc3545",
    Severity.HIGH: "#ff8c63",
    Severity.MEDIUM: "#f4c430",
    Severity.LOW: "#6dd5ed",
    Severity.INFO: "#6c757d",
}

_GRADE_STYLE: dict[str, str] = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "bold red",
}

_GRADE_COLOR: dict[str, str] = {
    "A": "green",
    "B": "green",
    "C": "yellow",
    "D": "red",
}

#: Hard cap on how many follower line numbers render inline in the
#: grouped-output title cell before the renderer collapses the rest
#: into "(and N more)". Larger lists balloon the row into a
#: multi-line wall on rules that fire many times on one resource.
_FOLLOWER_LINES_CAP = 10


def _display_path(text: str, limit: int = 50) -> str:
    """Resource string tuned for the terminal table cell.

    Backslashes render as forward slashes so a Windows scan reads the
    same as the docs and the HTML report. When a path is longer than
    *limit*, it's truncated on the *head* (``…ows/release.yml:172``) so
    the filename and line number, the part the operator acts on, always
    survive. Right-side truncation would keep the useless ``.github/wo``
    prefix and drop the filename, so we never do that.
    """
    text = text.replace("\\", "/")
    if len(text) <= limit:
        return text
    return "…" + text[-(limit - 1):]


def _visible(findings: list[Finding], threshold: Severity) -> list[Finding]:
    """Return findings at or above *threshold* severity, failures first."""
    min_rank = severity_rank(threshold)
    filtered = [f for f in findings if severity_rank(f.severity) >= min_rank]
    # Failures before passes, then most-severe first, then by check_id.
    filtered.sort(key=report_sort_key)
    return filtered


def _group_findings(
    failures: list[Finding],
) -> list[tuple[Finding, list[Finding]]]:
    """Collapse failures that share ``(check_id, resource-file)``.

    On a large repo the same rule fires across dozens of workflow
    files or container layers; the table fills with rows that read
    the same except for the line number. Grouping picks one
    representative per ``(check_id, file)`` and pushes the rest into
    a follower list rendered as a single dim "+N similar" row, with
    each follower's line number listed.

    ``file`` is the resource path without any line suffix when a
    ``Location`` is present, so two findings on different lines of
    the same workflow group together; two findings on the same line
    of different workflows do not.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    order: list[tuple[str, str]] = []
    for f in failures:
        # ``f.resource`` is the structured key; the Location (if any)
        # carries the line number separately. Group purely on the
        # resource so callers don't need to know about Locations.
        key = (f.check_id.upper(), f.resource)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    result: list[tuple[Finding, list[Finding]]] = []
    for key in order:
        members = groups[key]
        result.append((members[0], members[1:]))
    return result


def report_terminal(
    findings: list[Finding],
    score_result: ScoreResult,
    severity_threshold: Severity = Severity.INFO,
    console: Console | None = None,
    show_controls: bool = False,
    show_passed: bool = False,
    group_similar: bool = True,
    inline_explain: bool = False,
    incomplete_reason: str | None = None,
) -> None:
    """Print a rich-formatted report to the terminal.

    When ``incomplete_reason`` is set, the scan could not read
    everything it was asked to (a malformed file, a credential-less
    cloud probe). A confident green "Grade A" would be false
    reassurance in that case, since the grade only reflects what was
    actually parsed. The headline renders the grade in a caution style
    with an explicit "(incomplete)" tag plus a status line carrying the
    reason, so a partial scan can't be mistaken for a clean one.

    By default the table renders only failures: passed findings sit
    behind ``show_passed`` because on a real repo with 50 GHA checks
    against 10 workflow files, listing every PASS row produces
    hundreds of lines of green that bury the failures the user
    actually opened the report for. The headline summary still
    reports the failed-vs-passed counts.

    The per-finding panel shows the description, the recommendation,
    the CWE tags, and any multi-location list. The standards-mapping
    block (which can span 5+ frameworks and pad each panel out by
    ~30 lines) is suppressed unless ``show_controls`` is set.
    Compliance auditors who need either signal should use the JSON
    / SARIF outputs, which always carry the full ControlRef list.

    When ``group_similar`` is True (the default), repeated failures
    that share the same ``(check_id, resource)`` collapse to one
    visible row plus a "+N similar" follower row that lists the
    extra line numbers. Detail panels still render for the
    representative; the followers' line numbers are folded into its
    panel. Pass ``group_similar=False`` to render every row
    individually (matches the pre-1.x behavior).
    """
    if console is None:
        console = Console()

    grade = score_result["grade"]
    score = score_result["score"]
    grade_style = _GRADE_STYLE.get(grade, "white")
    summary = score_result.get("summary", {})

    # A degraded scan must not present as a confident pass. Override the
    # grade/bar palette to a caution color so a green "Grade A" can't
    # sit on top of an unparseable file or a failed cloud probe.
    incomplete = bool(incomplete_reason)
    if incomplete:
        grade_style = "bold yellow"

    total = len(findings)
    failed = sum(1 for f in findings if not f.passed)
    passed_count = total - failed

    # Severity failure breakdown, lower-case counts per the design system's
    # grading copy: "2 critical · 4 high · 7 medium · 3 low".
    sev_parts: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        data = summary.get(sev.value, {"passed": 0, "failed": 0})
        n_fail = data["failed"]
        if n_fail == 0:
            continue
        style = _SEVERITY_STYLE[sev]
        sev_parts.append(f"[{style}]{n_fail} {sev.value.lower()}[/{style}]")

    # Score bar
    bar_color = "yellow" if incomplete else _GRADE_COLOR.get(grade, "white")
    filled = score // 5
    bar = f"[{bar_color}]{'#' * filled}[/{bar_color}][dim]{'.' * (20 - filled)}[/dim]"

    # Headline grading copy:
    #     Score 47 / 100 · Grade D · 2 critical · 4 high · 7 medium · 3 low
    sep = "[dim] · [/dim]"
    grade_text = f"[{grade_style}]Grade {grade}[/{grade_style}]"
    if incomplete:
        grade_text += "[yellow] (incomplete)[/yellow]"
    headline_parts = [
        f"[bold]Score {score} / 100[/bold]",
        grade_text,
    ]
    headline_parts.extend(sev_parts)
    headline = sep.join(headline_parts)

    header_lines = [
        headline,
        f"{bar}  "
        f"[red]{failed} failed[/red] / [green]{passed_count} passed[/green] "
        f"[dim]({total} checks)[/dim]",
    ]
    if incomplete:
        header_lines.append(f"[yellow]incomplete scan: {incomplete_reason}[/yellow]")

    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold]Pipeline-Check[/bold]",
            border_style="yellow" if incomplete else "blue",
            padding=(0, 2),
        )
    )
    console.print()

    # Findings table. Passing findings render only when explicitly
    # requested — they're noise in the everyday "what's broken?"
    # workflow, and the headline already shows the pass count.
    visible = _visible(findings, severity_threshold)
    if not show_passed:
        visible = [f for f in visible if not f.passed]

    if not visible:
        if any(not f.passed for f in findings):
            # Failures exist but were filtered out by severity threshold.
            console.print(
                f"[green]No failures at or above {severity_threshold.value}.[/green] "
                f"[dim]Use --severity-threshold INFO to widen, "
                f"or pair it with --show-passed to list every check.[/dim]"
            )
        else:
            console.print(
                "[green]No findings.[/green] "
                "[dim]Use --show-passed to list every check that ran.[/dim]"
            )
        return

    # Split passes and failures up-front so the grouping logic below
    # only collapses failures (we don't want a passed-row group merging
    # with a failed-row group that happens to share a resource).
    visible_passes = [f for f in visible if f.passed]
    visible_failures = [f for f in visible if not f.passed]

    if group_similar:
        groups = _group_findings(visible_failures)
    else:
        groups = [(f, []) for f in visible_failures]

    # Confidence is HIGH for the overwhelming majority of rules (it's
    # the default a rule keeps unless it opts down to a heuristic
    # match). A column reading "high / high / high …" all the way down
    # is pure noise, so the column only appears when at least one shown
    # finding sits *below* HIGH. When it does appear, the HIGH rows dim
    # away and the MEDIUM / LOW ones catch the eye, which is exactly the
    # set worth a second look.
    conf_pool = visible_failures + (visible_passes if show_passed else [])
    show_conf = any(f.confidence != Confidence.HIGH for f in conf_pool)

    # No ``expand=True``: the table sizes to its content rather than
    # padding out to the full terminal width, so a scan on a 200-column
    # terminal doesn't leave a lake of empty space to the right. The
    # short columns never wrap; Resource and Title fold (and Resource is
    # head-truncated by ``_display_path``) so a narrow terminal degrades
    # to wrapped text instead of one-word-per-line truncation.
    table = Table(box=box.SIMPLE_HEAVY, pad_edge=False)
    table.add_column("", no_wrap=True)
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    if show_conf:
        table.add_column("Conf.", no_wrap=True)
    table.add_column("Resource", overflow="fold", max_width=50)
    # No max_width on Title: it's the flexible column. On a wide
    # terminal it takes its natural width (no wrap); on a narrow one
    # Rich shrinks it to fit and folds the text. Capping it would only
    # truncate titles when there's room to spare.
    table.add_column("Title", overflow="fold")

    def _render_row(f: Finding) -> None:
        """Add one finding to the table as a status/severity/resource row."""
        sev_style = _SEVERITY_STYLE.get(f.severity, "white")
        status = "[red]FAIL[/red]" if not f.passed else "[green]PASS[/green]"
        # Build the resource cell: append the primary line number when
        # the rule emitted a Location, then forward-slash and
        # head-truncate via ``_display_path``. Escape through
        # ``rich.markup.escape`` because real content carries literal
        # ``[...]`` tokens (YAML lists, TF refs like
        # ``[aws_subnet.foo.id]``, capabilities ``[ALL]``) that the
        # table renderer would otherwise parse as Rich style markup and
        # silently strip.
        resource_full = f.resource
        if f.locations:
            primary = f.locations[0]
            if primary.start_line is not None:
                resource_full = f"{f.resource}:{primary.start_line}"
        resource_cell = rich_escape(_display_path(resource_full))
        cells = [
            status,
            f.check_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
        ]
        if show_conf:
            conf_style = _CONFIDENCE_STYLE.get(f.confidence, "")
            conf_label = _CONF_LABEL.get(f.confidence, f.confidence.value.lower())
            cells.append(
                f"[{conf_style}]{conf_label}[/{conf_style}]"
                if conf_style else conf_label
            )
        cells.append(resource_cell)
        cells.append(rich_escape(f.title))
        table.add_row(*cells)

    # Leading blank cells a follower-summary row needs before the Title
    # column (which carries the "+N more" text): one per column except
    # Title, so one fewer when the Conf. column is hidden.
    n_blanks = 5 if show_conf else 4

    # Failures first, in group order.
    for representative, followers in groups:
        _render_row(representative)
        if not followers:
            continue
        # Collect line numbers from the followers that have a Location.
        lines = [
            str(f.locations[0].start_line)
            for f in followers
            if f.locations and f.locations[0].start_line is not None
        ]
        if lines:
            # Cap the inline list so a rule that fires 60+ times on
            # one resource (k8s manifest sets) doesn't balloon the
            # Title column into a multi-line wall.
            shown = lines[:_FOLLOWER_LINES_CAP]
            extra = len(lines) - len(shown)
            lines_phrase = ", ".join(shown)
            if extra:
                lines_phrase += f" (and {extra} more)"
            follower_cell = (
                f"[dim]      + {len(followers)} more on lines "
                f"{lines_phrase} (rerun with --no-group to expand)[/dim]"
            )
        else:
            follower_cell = (
                f"[dim]      + {len(followers)} similar finding(s) "
                f"(rerun with --no-group to expand)[/dim]"
            )
        # Render the follower-summary in the Title column so the row
        # height stays one line and the eye scans down the Check column.
        table.add_row(*([""] * n_blanks), follower_cell)

    # Passes (only present when show_passed is set).
    for f in visible_passes:
        _render_row(f)

    console.print(table)

    if not visible_failures:
        return

    console.print()
    for representative, followers in groups:
        f = representative
        style = _SEVERITY_STYLE.get(f.severity, "white")
        cwe_line = ""
        if f.cwe:
            cwe_line = f"\n[dim]CWE: {rich_escape(', '.join(f.cwe))}[/dim]"
        controls_text = ""
        if f.controls and show_controls:
            controls_text = "\n[bold]Controls:[/bold]\n" + "\n".join(
                f"  {rich_escape('[' + c.standard_title + '] ' + c.label())}"
                for c in f.controls
            )
        # When the rule emitted >1 location OR there are grouped
        # followers with locations, list every offending line in the
        # panel so users see every hit at a glance.
        locations_text = ""
        all_lines: list[int] = [
            loc.start_line for loc in f.locations
            if loc.start_line is not None
        ]
        for follower in followers:
            if follower.locations and follower.locations[0].start_line is not None:
                all_lines.append(follower.locations[0].start_line)
        if len(all_lines) > 1:
            shown_lines = all_lines[:_FOLLOWER_LINES_CAP]
            extra = len(all_lines) - len(shown_lines)
            lines_csv = ", ".join(str(n) for n in shown_lines)
            if extra:
                lines_csv += f" (and {extra} more)"
            path = f.locations[0].path if f.locations else f.resource
            locations_text = (
                f"\n[bold]Locations:[/bold] {rich_escape(path)}:{lines_csv}"
            )
        elif followers:
            locations_text = (
                f"\n[dim]Grouped with {len(followers)} similar finding(s) "
                f"on the same resource.[/dim]"
            )
        # ``--inline-explain`` surfaces the rule's ``exploit_example``
        # (when one is recorded) right under the recommendation so the
        # operator doesn't need a separate ``--explain CHECK_ID``
        # round-trip. The gate lives in ``inline_exploit`` so SARIF,
        # JUnit, markdown, and codequality make the same decision. The
        # example is escaped through ``rich.markup.escape`` because real
        # exploit snippets contain literal ``[...]`` tokens (YAML lists
        # like ``types: [opened, edited]``, Terraform refs like
        # ``subnets = [aws_subnet.foo.id]``, K8s capabilities ``[ALL]``)
        # that the Panel renderer would otherwise parse as Rich style
        # markup and silently strip. Label matches ``--explain`` and the
        # HTML report so the same field reads the same on every surface.
        exploit_text = ""
        exploit = inline_exploit(f, inline_explain)
        if exploit:
            exploit_text = (
                f"\n[bold]Proof of exploit:[/bold]\n{rich_escape(exploit)}"
            )
        # Forward-slash the panel-title resource so a Windows scan reads
        # like the docs (the table cell already does this via
        # ``_display_path``).
        panel_resource = rich_escape(f.resource.replace("\\", "/"))
        console.print(
            Panel(
                f"{rich_escape(f.description)}\n\n"
                f"[bold]Recommendation:[/bold] {rich_escape(f.recommendation)}"
                f"{cwe_line}{controls_text}{locations_text}{exploit_text}",
                title=(
                    f"[{style}]{f.check_id}[/{style}]  "
                    f"{rich_escape(f.title)}  "
                    f"[dim]{panel_resource}[/dim]"
                ),
                border_style="dim",
                padding=(0, 2),
            )
        )


def next_steps_tip(
    findings: list[Finding],
    severity_threshold: Severity = Severity.INFO,
) -> str | None:
    """One-line "what next" nudge for the terminal, or None.

    The findings panels explain *why* each finding fired; this says
    *what to do next*. Returns None when there's nothing actionable
    (no failures at or above the threshold). The CLI renders it as the
    final line of a terminal scan, after the table, panels, chains, and
    inventory, so even a passing run with findings points somewhere.
    The gate trailer (stderr, only when the gate trips) is the CI-log
    analog; this is the interactive nudge.
    """
    min_rank = severity_rank(severity_threshold)
    fails = [
        f for f in findings
        if not f.passed and severity_rank(f.severity) >= min_rank
    ]
    if not fails:
        return None
    fails.sort(key=failure_sort_key)
    from .autofix import available_fixers

    fixers = set(available_fixers())
    n_fixable = sum(1 for f in fails if f.check_id.upper() in fixers)
    top_id = fails[0].check_id
    tip = (
        f"[dim]Next →[/dim] inspect a rule: "
        f"[bold]pipeline_check explain {top_id}[/bold]"
    )
    if n_fixable:
        tip += (
            f"   [dim]·[/dim]   autofix {n_fixable} of {len(fails)}: "
            f"[bold]pipeline_check --fix --apply[/bold]"
        )
    return tip


def report_json(
    findings: list[Finding],
    score_result: ScoreResult,
    tool_version: str = "",
    inventory: list[Component] | None = None,
    chains: list[Chain] | None = None,
) -> str:
    """Serialize all findings and the score to a JSON string.

    The payload carries ``schema_version`` (bumped on breaking format
    changes) and ``tool_version`` (the pipeline_check release that
    produced it) at the top level so downstream consumers can version-
    branch without guessing.

    When *inventory* is supplied the payload gains an ``inventory``
    top-level array. Consumers can feature-detect it; it's omitted
    (not just empty) when ``--inventory`` wasn't requested, so
    dashboards can distinguish "nothing found" from "not asked for".

    When *chains* is supplied the payload gains a ``chains`` top-level
    array, multi-finding attack-chain correlations. Always present
    (possibly empty) when chain evaluation ran; omitted when the caller
    explicitly disabled chains via ``--no-chains``.
    """
    payload: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool_version": tool_version or "0.0.0",
        "score": score_result,
        "findings": [f.to_dict() for f in findings],
    }
    if inventory is not None:
        payload["inventory"] = [c.to_dict() for c in inventory]
    if chains is not None:
        payload["chains"] = [c.to_dict() for c in chains]
    return json.dumps(payload, indent=2)


def report_chains_terminal(
    chains: list[Chain],
    console: Console | None = None,
) -> None:
    """Render attack chains as one panel per chain to the terminal.

    A chain is the strongest signal pipeline_check produces, multiple
    findings combine into a real attack path. Always rendered after
    the findings table (and before inventory), with a colored border
    matching the chain's severity so a CRITICAL chain is immediately
    visible even on a busy report.
    """
    if console is None:
        console = Console()
    if not chains:
        return
    console.print()
    console.print(
        Panel(
            (
                f"[bold]{len(chains)} attack chain(s) detected[/bold], "
                "multiple findings combine into a real attack path. "
                "Fix any one finding in a chain to break it."
            ),
            title="[bold red]Attack Chains[/bold red]",
            border_style="red",
            padding=(0, 2),
        )
    )
    for chain in chains:
        sev_style = _SEVERITY_STYLE.get(chain.severity, "white")
        conf_style = _CONFIDENCE_STYLE.get(chain.confidence, "")
        # Escape narrative/summary/recommendation/references: chain prose
        # quotes bracketed payloads and resource refs that would
        # otherwise be parsed as Rich style markup and stripped.
        body_lines = [
            f"[bold]{rich_escape(chain.summary)}[/bold]",
            "",
            rich_escape(chain.narrative),
            "",
            f"[bold]Triggering checks:[/bold] "
            f"{rich_escape(', '.join(chain.triggering_check_ids))}",
        ]
        if chain.confirmed_reachable:
            label = (
                "✓ Reachability confirmed (dataflow)"
                if chain.via_dataflow
                else "✓ Reachability confirmed"
            )
            reach_line = f"[bold green]{label}[/bold green]"
            if chain.reachability_note:
                reach_line += f": {rich_escape(chain.reachability_note)}"
            body_lines.append(reach_line)
        if chain.mitre_attack:
            body_lines.append(
                f"[bold]MITRE ATT&CK:[/bold] "
                f"{rich_escape(', '.join(chain.mitre_attack))}"
            )
        if chain.kill_chain_phase:
            body_lines.append(
                f"[bold]Kill chain:[/bold] {rich_escape(chain.kill_chain_phase)}"
            )
        body_lines.append(
            f"[bold]Recommendation:[/bold] {rich_escape(chain.recommendation)}"
        )
        if chain.references:
            body_lines.append("[bold]References:[/bold]")
            for ref in chain.references:
                body_lines.append(f"  - {rich_escape(ref)}")
        conf_label = (
            f"[{conf_style}]{chain.confidence.value}[/{conf_style}]"
            if conf_style else chain.confidence.value
        )
        console.print(
            Panel(
                "\n".join(body_lines),
                title=(
                    f"[{sev_style}]{chain.chain_id}[/{sev_style}]  "
                    f"{rich_escape(chain.title)}  "
                    f"[dim](severity: {chain.severity.value}, "
                    f"confidence: {conf_label})[/dim]"
                ),
                border_style=sev_style,
                padding=(0, 2),
            )
        )


def report_inventory_terminal(
    inventory: list[Component], console: Console | None = None,
) -> None:
    """Render a compact table of scanned components to the terminal."""
    if console is None:
        console = Console()
    if not inventory:
        console.print("[dim]Inventory: no components discovered.[/dim]")
        return
    table = Table(
        title=f"Inventory, {len(inventory)} component(s)",
        box=box.SIMPLE_HEAD,
        show_lines=False,
    )
    table.add_column("Provider", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Identifier")
    table.add_column("Source", style="dim")
    for c in inventory:
        table.add_row(c.provider, c.type, c.identifier, c.source)
    console.print(table)
