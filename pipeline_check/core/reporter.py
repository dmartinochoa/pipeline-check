"""Output formatters -- terminal (rich) and JSON."""

import json
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .chains import Chain
from .checks.base import Confidence, Finding, Severity, severity_rank
from .inventory import Component
from .scorer import ScoreResult

_CONFIDENCE_STYLE: dict[Confidence, str] = {
    Confidence.HIGH: "bold",
    Confidence.MEDIUM: "dim",
    Confidence.LOW: "dim italic",
}

# Bump when the JSON payload shape changes in a way consumers need to
# branch on (e.g. a new top-level key, a renamed field). Minor-revision
# adds (appending an optional field) do NOT require a version bump.
JSON_SCHEMA_VERSION = "1.1"

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
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


def _visible(findings: list[Finding], threshold: Severity) -> list[Finding]:
    """Return findings at or above *threshold* severity, failures first."""
    min_rank = severity_rank(threshold)
    filtered = [f for f in findings if severity_rank(f.severity) >= min_rank]
    # Sort: failures before passes, then most-severe first, then by check_id.
    filtered.sort(
        key=lambda f: (f.passed, -severity_rank(f.severity), f.check_id)
    )
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
) -> None:
    """Print a rich-formatted report to the terminal.

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
    bar_color = _GRADE_COLOR.get(grade, "white")
    filled = score // 5
    bar = f"[{bar_color}]{'#' * filled}[/{bar_color}][dim]{'.' * (20 - filled)}[/dim]"

    # Headline grading copy:
    #     Score 47 / 100 · Grade D · 2 critical · 4 high · 7 medium · 3 low
    sep = "[dim] · [/dim]"
    headline_parts = [
        f"[bold]Score {score} / 100[/bold]",
        f"[{grade_style}]Grade {grade}[/{grade_style}]",
    ]
    headline_parts.extend(sev_parts)
    headline = sep.join(headline_parts)

    header_lines = [
        headline,
        f"{bar}  "
        f"[red]{failed} failed[/red] / [green]{passed_count} passed[/green] "
        f"[dim]({total} checks)[/dim]",
    ]

    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold]Pipeline-Check[/bold]",
            border_style="blue",
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

    table = Table(box=box.SIMPLE_HEAVY, expand=True, pad_edge=False)
    table.add_column("", no_wrap=True, width=4)
    table.add_column("Check", style="bold", no_wrap=True, width=8)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Conf.", no_wrap=True, width=7)
    table.add_column("Resource", overflow="fold", max_width=28)
    table.add_column("Title", ratio=1)

    def _render_row(f: Finding) -> None:
        sev_style = _SEVERITY_STYLE.get(f.severity, "white")
        conf_style = _CONFIDENCE_STYLE.get(f.confidence, "")
        status = "[red]FAIL[/red]" if not f.passed else "[green]PASS[/green]"
        conf_label = f.confidence.value[:3]
        conf_cell = (
            f"[{conf_style}]{conf_label}[/{conf_style}]"
            if conf_style else conf_label
        )
        resource_cell = f.resource
        if f.locations:
            primary = f.locations[0]
            if primary.start_line is not None:
                resource_cell = f"{f.resource}:{primary.start_line}"
        table.add_row(
            status,
            f.check_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            conf_cell,
            resource_cell,
            f.title,
        )

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
        table.add_row("", "", "", "", "", follower_cell)

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
            cwe_line = f"\n[dim]CWE: {', '.join(f.cwe)}[/dim]"
        controls_text = ""
        if f.controls and show_controls:
            controls_text = "\n[bold]Controls:[/bold]\n" + "\n".join(
                f"  [{c.standard_title}] {c.label()}" for c in f.controls
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
            locations_text = f"\n[bold]Locations:[/bold] {path}:{lines_csv}"
        elif followers:
            locations_text = (
                f"\n[dim]Grouped with {len(followers)} similar finding(s) "
                f"on the same resource.[/dim]"
            )
        console.print(
            Panel(
                f"{f.description}\n\n"
                f"[bold]Recommendation:[/bold] {f.recommendation}"
                f"{cwe_line}{controls_text}{locations_text}",
                title=(
                    f"[{style}]{f.check_id}[/{style}]  "
                    f"{f.title}  [dim]{f.resource}[/dim]"
                ),
                border_style="dim",
                padding=(0, 2),
            )
        )


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
        body_lines = [
            f"[bold]{chain.summary}[/bold]",
            "",
            chain.narrative,
            "",
            f"[bold]Triggering checks:[/bold] {', '.join(chain.triggering_check_ids)}",
        ]
        if chain.mitre_attack:
            body_lines.append(
                f"[bold]MITRE ATT&CK:[/bold] {', '.join(chain.mitre_attack)}"
            )
        if chain.kill_chain_phase:
            body_lines.append(f"[bold]Kill chain:[/bold] {chain.kill_chain_phase}")
        body_lines.append(f"[bold]Recommendation:[/bold] {chain.recommendation}")
        if chain.references:
            body_lines.append("[bold]References:[/bold]")
            for ref in chain.references:
                body_lines.append(f"  - {ref}")
        conf_label = (
            f"[{conf_style}]{chain.confidence.value}[/{conf_style}]"
            if conf_style else chain.confidence.value
        )
        console.print(
            Panel(
                "\n".join(body_lines),
                title=(
                    f"[{sev_style}]{chain.chain_id}[/{sev_style}]  "
                    f"{chain.title}  "
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
