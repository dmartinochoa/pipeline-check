"""JSON Lines (newline-delimited JSON) findings stream.

One JSON object per failing finding, one per line, using the same
per-finding shape as the ``json`` output's ``findings`` array
(``Finding.to_dict()``). Unlike the single ``json`` document, a JSONL
stream has no wrapping array or score block, so it is appended to and
parsed line by line: the native ingest format for log pipelines (Splunk
/ ELK / Datadog) and the shape a shell loop or ``jq -c`` can process
without loading the whole report into memory.

Only failing findings are emitted, mirroring the SARIF / CSV / Code
Quality reporters (passing checks aren't actionable). Each line is
compact-encoded with the keys in ``Finding.to_dict()`` order, so
``--output jsonl >> findings.log`` across many repos / runs yields one
valid, stable, append-only record set.
"""
from __future__ import annotations

import json

from .checks.base import Finding
from .report_view import ReportView


def report_jsonl(findings: list[Finding], inline_explain: bool = False) -> str:
    """Render failing *findings* as JSON Lines (one object per line).

    Each line is ``Finding.to_dict()`` (the same shape as the ``json``
    output's ``findings`` entries), compact-encoded. ``inline_explain``
    is accepted for call-site uniformity with the other text reporters
    but has no effect here: the structured object always carries the
    ``exploit_example`` field, so the consumer reads it directly.
    """
    lines = [
        json.dumps(f.to_dict(), separators=(",", ":"))
        for f in ReportView(findings).failed
    ]
    return "\n".join(lines) + ("\n" if lines else "")
