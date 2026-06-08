"""Per-repo false-positive annotation store.

When a user is sure a finding is a false positive on a specific
file, ``pipeline_check --annotate-fp CHECK_ID RESOURCE`` records
the (check_id, resource) pair into a local JSON file. Subsequent
scans demote that finding's confidence one rung (HIGH -> MEDIUM,
MEDIUM -> LOW), keeping it visible in reports but allowing
``--min-confidence MEDIUM`` to filter it out at the gate without
hand-editing an ignore-file entry.

The file is a plain JSON document with a versioned schema so the
shape can grow (e.g. an AST-anchor hash) without breaking older
readers:

    {
      "version": 1,
      "annotations": [
        {
          "check_id": "GHA-016",
          "resource": ".github/workflows/ci.yml",
          "annotated_at": "2026-05-10T12:34:56Z"
        }
      ]
    }

No telemetry, no upload. The file lives in the repository and
travels with the code, so demotion is a property of the repo,
not of any one developer's machine.
"""
from __future__ import annotations

import datetime as _dt
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .checks.base import Confidence

#: Default filename for the annotation store. Lives at the repository
#: root so every clone of the repo sees the same demotion set.
DEFAULT_FP_PATH = ".pipeline-check-fp.json"

#: Schema version of the on-disk file. Bump when the entry shape
#: changes incompatibly; readers should still tolerate older versions.
FP_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class FPAnnotation:
    """One recorded false-positive annotation."""

    check_id: str
    resource: str
    annotated_at: str = ""

    def matches(self, check_id: str, resource: str) -> bool:
        return (
            self.check_id.upper() == check_id.upper()
            and self.resource == resource
        )


def _now_iso() -> str:
    """Current UTC time in ISO 8601 form. Extracted so tests can mock it."""
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_annotations(path: str | Path = DEFAULT_FP_PATH) -> list[FPAnnotation]:
    """Read *path* and return the parsed annotation list.

    Missing files return an empty list. Unparseable files (corrupt
    JSON, wrong schema, missing keys) also return an empty list, the
    annotation file is never load-bearing for correctness, only for
    confidence calibration. A stale-but-valid entry that no longer
    matches any finding is silently inert; we don't try to garbage-
    collect.
    """
    p = Path(path)
    if not p.is_file():
        return []
    try:
        text = p.read_text(encoding="utf-8")
        doc = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError):
        return []
    if not isinstance(doc, dict):
        return []
    raw_entries = doc.get("annotations")
    if not isinstance(raw_entries, list):
        return []
    out: list[FPAnnotation] = []
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        cid = entry.get("check_id")
        res = entry.get("resource")
        if not isinstance(cid, str) or not isinstance(res, str):
            continue
        ts_val = entry.get("annotated_at", "")
        ts = ts_val if isinstance(ts_val, str) else ""
        out.append(FPAnnotation(
            check_id=cid.upper(), resource=res, annotated_at=ts,
        ))
    return out


def append_annotation(
    check_id: str,
    resource: str,
    *,
    path: str | Path = DEFAULT_FP_PATH,
) -> bool:
    """Append a (check_id, resource) annotation to *path*.

    Returns True when a new entry is written, False when the same
    pair was already present (idempotent: re-running ``--annotate-fp``
    with the same args is a no-op so users can run it from CI without
    accumulating duplicates). Creates *path* if it doesn't exist.
    """
    cid = check_id.strip().upper()
    res = resource.strip()
    if not cid or not res:
        raise ValueError(
            "annotate-fp requires a non-empty check id and resource"
        )

    p = Path(path)
    existing = load_annotations(p)
    if any(a.matches(cid, res) for a in existing):
        return False

    new_entry = FPAnnotation(
        check_id=cid, resource=res, annotated_at=_now_iso(),
    )
    serialized = {
        "version": FP_SCHEMA_VERSION,
        "annotations": [
            {
                "check_id": a.check_id,
                "resource": a.resource,
                "annotated_at": a.annotated_at,
            }
            for a in (*existing, new_entry)
        ],
    }
    p.write_text(json.dumps(serialized, indent=2) + "\n", encoding="utf-8")
    return True


def demote_one_rung(c: Confidence) -> Confidence:
    """Return the confidence one rung below *c*.

    HIGH -> MEDIUM, MEDIUM -> LOW, LOW -> LOW (saturates). Callers
    use this from the Scanner's per-finding loop when an annotation
    matches the finding.
    """
    if c == Confidence.HIGH:
        return Confidence.MEDIUM
    if c == Confidence.MEDIUM:
        return Confidence.LOW
    return Confidence.LOW


def annotation_index(
    annotations: list[FPAnnotation],
) -> dict[tuple[str, str], FPAnnotation]:
    """Return ``{(check_id_upper, resource): annotation}`` for fast lookup.

    The Scanner calls this once per scan and then walks every finding
    against the index in O(1) per finding.
    """
    return {(a.check_id, a.resource): a for a in annotations}


def fp_stats(
    annotations: list[FPAnnotation],
) -> list[tuple[str, int]]:
    """Return ``[(check_id, count), ...]`` sorted by count desc, then id asc.

    Surfaces which rules accumulate the most false-positive votes
    across the repo so rule authors can prioritize triage. Ties
    broken by lexical id so the output is stable.
    """
    counts: Counter[str] = Counter(a.check_id for a in annotations)
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))


__all__ = [
    "DEFAULT_FP_PATH",
    "FP_SCHEMA_VERSION",
    "FPAnnotation",
    "annotation_index",
    "append_annotation",
    "demote_one_rung",
    "fp_stats",
    "load_annotations",
]
