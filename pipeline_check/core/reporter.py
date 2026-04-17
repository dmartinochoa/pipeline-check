"""Output formatters -- terminal (rich) and JSON."""

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .checks.base import Confidence, Finding, Severity, severity_rank
from .inventory import Component

_CONFIDENCE_STYLE: dict[Confidence, str] = {
    Confidence.HIGH: "bold",
    Confidence.MEDIUM: "dim",
    Confidence.LOW: "dim italic",
}

# Bump when the JSON payload shape changes in a way consumers need to
# branch on (e.g. a new top-level key, a renamed field). Minor-revision
# adds (appending an optional field) do NOT require a version bump.
JSON_SCHEMA_VERSION = "1.0"

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


def _visible(findings: list[Finding], threshold: Severity) -> list[Finding]:
    """Return findings at or above *threshold* severity, failures first."""
    min_rank = severity_rank(threshold)
    filtered = [f for f in findings if severity_rank(f.severity) >= min_rank]
    # Sort: failures before passes, then most-severe first, then by check_id.
    filtered.sort(
        key=lambda f: (f.passed, -severity_rank(f.severity), f.check_id)
    )
    return filtered


def report_terminal(
    findings: list[Finding],
    score_result: dict,
    severity_threshold: Severity = Severity.INFO,
    console: Console | None = None,
) -> None:
    """Print a rich-formatted report to the terminal."""
    if console is None:
        console = Console()

    grade = score_result["grade"]
    score = score_result["score"]
    grade_style = _GRADE_STYLE.get(grade, "white")
    summary = score_result.get("summary", {})

    total = len(findings)
    failed = sum(1 for f in findings if not f.passed)
    passed_count = total - failed

    # Severity failure breakdown
    sev_parts: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        data = summary.get(sev.value, {"passed": 0, "failed": 0})
        n_fail = data["failed"]
        if n_fail == 0:
            continue
        style = _SEVERITY_STYLE[sev]
        sev_parts.append(f"[{style}]{n_fail} {sev.value}[/{style}]")

    # Score bar
    bar_color = _GRADE_COLOR.get(grade, "white")
    filled = score // 5
    bar = f"[{bar_color}]{'#' * filled}[/{bar_color}][dim]{'.' * (20 - filled)}[/dim]"

    header_lines = [
        f"[{grade_style}]Grade {grade}[/{grade_style}]   "
        f"{bar} {score}/100\n"
        f"[red]{failed} failed[/red] / [green]{passed_count} passed[/green] "
        f"[dim]({total} checks)[/dim]",
    ]
    if sev_parts:
        header_lines.append("Failures: " + "  ".join(sev_parts))

    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold]PipelineCheck[/bold]",
            border_style="blue",
            padding=(0, 2),
        )
    )
    console.print()

    # Findings table
    visible = _visible(findings, severity_threshold)

    if not visible:
        console.print("[green]No findings at or above the severity threshold.[/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY, expand=True, pad_edge=False)
    table.add_column("", no_wrap=True, width=4)
    table.add_column("Check", style="bold", no_wrap=True, width=8)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Conf.", no_wrap=True, width=7)
    table.add_column("Resource", overflow="fold", max_width=28)
    table.add_column("Title", ratio=1)

    for f in visible:
        sev_style = _SEVERITY_STYLE.get(f.severity, "white")
        conf_style = _CONFIDENCE_STYLE.get(f.confidence, "")
        status = "[red]FAIL[/red]" if not f.passed else "[green]PASS[/green]"
        # Abbreviate confidence to fit column width. LOW confidence is
        # visually de-emphasised so HIGH failures stand out when
        # scanning a long table.
        conf_label = f.confidence.value[:3]
        conf_cell = (
            f"[{conf_style}]{conf_label}[/{conf_style}]" if conf_style else conf_label
        )
        table.add_row(
            status,
            f.check_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            conf_cell,
            f.resource,
            f.title,
        )

    console.print(table)

    # Detail panels for failures
    failures = [f for f in visible if not f.passed]
    if not failures:
        return

    console.print()
    for f in failures:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        cwe_line = ""
        if f.cwe:
            cwe_line = f"\n[dim]CWE: {', '.join(f.cwe)}[/dim]"
        controls_text = ""
        if f.controls:
            controls_text = "\n[bold]Controls:[/bold]\n" + "\n".join(
                f"  [{c.standard_title}] {c.label()}" for c in f.controls
            )
        console.print(
            Panel(
                f"{f.description}\n\n"
                f"[bold]Recommendation:[/bold] {f.recommendation}"
                f"{cwe_line}{controls_text}",
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
    score_result: dict,
    tool_version: str = "",
    inventory: list[Component] | None = None,
) -> str:
    """Serialise all findings and the score to a JSON string.

    The payload carries ``schema_version`` (bumped on breaking format
    changes) and ``tool_version`` (the pipeline_check release that
    produced it) at the top level so downstream consumers can version-
    branch without guessing.

    When *inventory* is supplied the payload gains an ``inventory``
    top-level array. Consumers can feature-detect it; it's omitted
    (not just empty) when ``--inventory`` wasn't requested, so
    dashboards can distinguish "nothing found" from "not asked for".
    """
    payload: dict = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool_version": tool_version or "0.0.0",
        "score": score_result,
        "findings": [f.to_dict() for f in findings],
    }
    if inventory is not None:
        payload["inventory"] = [c.to_dict() for c in inventory]
    return json.dumps(payload, indent=2)


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
        title=f"Inventory — {len(inventory)} component(s)",
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
