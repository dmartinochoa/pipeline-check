"""Output formatters -- terminal (rich) and JSON."""

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .checks.base import Finding, Severity, severity_rank

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

    # Header
    console.print(
        Panel(
            f"[{grade_style}]Grade: {grade}   Score: {score}/100[/{grade_style}]",
            title="[bold]PipelineCheck -- CI/CD Security Report[/bold]",
            border_style="blue",
            padding=(0, 2),
        )
    )

    # Per-severity summary bar
    summary = score_result.get("summary", {})
    parts: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        data = summary.get(sev.value, {"passed": 0, "failed": 0})
        total = data["passed"] + data["failed"]
        if total == 0:
            continue
        style = _SEVERITY_STYLE[sev]
        parts.append(
            f"[{style}]{sev.value}[/{style}] {data['failed']}x / {data['passed']}v"
        )
    if parts:
        console.print("  " + "   ".join(parts))
    console.print()

    # Findings table
    visible = _visible(findings, severity_threshold)

    if not visible:
        console.print("[green]No findings at or above the severity threshold.[/green]")
        return

    table = Table(box=box.ROUNDED, show_lines=True, expand=True, highlight=True)
    table.add_column("ID", style="bold", no_wrap=True, width=8)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Status", no_wrap=True, width=6)
    table.add_column("Resource", overflow="fold", max_width=30)
    table.add_column("Title")
    table.add_column("Controls", overflow="fold", max_width=36)

    for f in visible:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        status = "[green]PASS[/green]" if f.passed else "[red]FAIL[/red]"
        controls_cell = ", ".join(c.control_id for c in f.controls) or "-"
        table.add_row(
            f.check_id,
            f"[{style}]{f.severity.value}[/{style}]",
            status,
            f.resource,
            f.title,
            controls_cell,
        )

    console.print(table)

    # Detail panels for failures only
    failures = [f for f in visible if not f.passed]
    if not failures:
        return

    console.print("\n[bold]Failure Details[/bold]")
    for f in failures:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        controls_text = (
            "\n".join(
                f"  - [{c.standard_title}] {c.label()}" for c in f.controls
            )
            if f.controls
            else "  (none mapped)"
        )
        console.print(
            Panel(
                f"[bold]Description:[/bold]\n{f.description}\n\n"
                f"[bold]Recommendation:[/bold]\n{f.recommendation}\n\n"
                f"[bold]Compliance controls:[/bold]\n{controls_text}",
                title=(
                    f"[{style}][{f.check_id}] {f.title}[/{style}]"
                    f"  --  {f.resource}"
                ),
                border_style="dim",
                padding=(1, 2),
            )
        )


def report_json(
    findings: list[Finding],
    score_result: dict,
    tool_version: str = "",
) -> str:
    """Serialise all findings and the score to a JSON string.

    The payload carries ``schema_version`` (bumped on breaking format
    changes) and ``tool_version`` (the pipeline_check release that
    produced it) at the top level so downstream consumers can version-
    branch without guessing.
    """
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool_version": tool_version or "0.0.0",
        "score": score_result,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
