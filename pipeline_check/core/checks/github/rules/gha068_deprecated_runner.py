"""GHA-068. ``runs-on:`` targets an end-of-life GitHub-hosted runner.

zizmor proposal #260 / #827. GitHub retires hosted-runner images on
a published schedule. ``ubuntu-18.04`` is retired
(2023-04-01); ``ubuntu-20.04`` is in extended-support and retires
2025-04-15. ``macos-11`` retired 2024-06-28. ``windows-2019`` is
sunsetting through 2026.

Workflows pinned to a retired image:

  * Stop receiving security patches for the runner OS.
  * Eventually fail at queue time when GitHub removes the label.
  * On retirement day, get silently rerouted to a newer image,
    which may break build steps that depended on the old toolchain.

None of those failure modes are catastrophic in isolation, but
they're all avoidable by pinning to a current major.
"""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs

#: ``runs-on: ${{ matrix.os }}`` — an OS matrix is the most common way a
#: deprecated image reaches a job, so resolve the referenced axis.
_MATRIX_REF_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

RULE = Rule(
    id="GHA-068",
    title="``runs-on:`` targets an end-of-life hosted-runner image",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-1104",),  # Use of Unmaintained Third Party Components
    recommendation=(
        "Bump to a supported image label. ``ubuntu-latest`` /"
        "``ubuntu-24.04``, ``macos-latest`` / ``macos-14``, "
        "``windows-latest`` / ``windows-2022``. Pin to a specific "
        "major when reproducibility matters (``ubuntu-24.04``); "
        "use ``-latest`` only when the workflow tolerates drift. "
        "GitHub publishes the retirement schedule at "
        "https://github.com/actions/runner-images?tab=readme-ov-file"
        "#available-images, audit the matrix periodically as new "
        "images deprecate."
    ),
    docs_note=(
        "Fires when a job's ``runs-on:`` (or any matrix-expanded "
        "value of it) names a retired or imminently-retired hosted "
        "runner image:\n\n"
        "* **Ubuntu retired:** ``ubuntu-18.04``, ``ubuntu-20.04``.\n"
        "* **macOS retired:** ``macos-10.15``, ``macos-11``, "
        "``macos-12``.\n"
        "* **Windows retired:** ``windows-2016``, ``windows-2019``.\n\n"
        "Self-hosted labels (any value that doesn't match a hosted "
        "image label) are not flagged here, GHA-012 covers the "
        "self-hosted-runner risk separately. List-shaped "
        "``runs-on:`` values (``[self-hosted, linux, x64]``) are "
        "treated as self-hosted and skipped."
    ),
    known_fp=(
        "A repository that intentionally pins to an older image "
        "for archive-build reproducibility (rare, but valid). "
        "Suppress per-job via ignore-file when the operator has "
        "documented the trade-off. Note that GitHub may stop "
        "serving the image entirely at some point; the suppression "
        "should be re-audited annually.",
    ),
    incident_refs=(
        "GitHub Actions runner-images retirement schedule: "
        "https://github.com/actions/runner-images",
        "zizmor proposal #260 / #827 (deprecated runner audit): "
        "https://github.com/zizmorcore/zizmor/issues/260",
    ),
    exploit_example=(
        "# Vulnerable: ``ubuntu-18.04`` was retired 2023-04-01.\n"
        "# GitHub rerouted those jobs to a newer image and the\n"
        "# action.yml's PATH and pre-installed toolchain shifted\n"
        "# silently. Any workflow that depended on the retired\n"
        "# image's exact behavior now diverges.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-18.04\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: pin to a supported image.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh"
    ),
)


#: Hosted-runner images GitHub has retired or scheduled for
#: retirement. Mapped to the public retirement notice for traceability.
_DEPRECATED_RUNNERS: dict[str, str] = {
    # Ubuntu
    "ubuntu-18.04": "retired 2023-04-01",
    "ubuntu-20.04": "retiring 2025-04-15",
    # macOS
    "macos-10.15": "retired 2022-08-30",
    "macos-11": "retired 2024-06-28",
    "macos-12": "retired 2024-12-04",
    # Windows
    "windows-2016": "retired 2022-03-15",
    "windows-2019": "retiring 2026-04-01",
}


def _runs_on_labels(value: Any) -> list[str]:
    """Return the runs-on label(s) for a job, normalized to lowercase.

    Handles:

      * String shape: ``runs-on: ubuntu-latest``.
      * List shape: ``runs-on: [self-hosted, linux, x64]``. Lists
        are usually self-hosted-style and we return all entries so
        callers can detect a deprecated label even when mixed with
        ``self-hosted``.
      * Dict shape (``group:`` / ``labels:`` selector): the
        ``labels:`` field carries the actual matchers. The ``group:``
        is a runner-group name, not an image, so we skip it.
    """
    if isinstance(value, str):
        return [value.strip().lower()]
    if isinstance(value, list):
        return [str(v).strip().lower() for v in value if isinstance(v, str)]
    if isinstance(value, dict):
        labels = value.get("labels")
        if isinstance(labels, str):
            return [labels.strip().lower()]
        if isinstance(labels, list):
            return [str(v).strip().lower() for v in labels if isinstance(v, str)]
    return []


def _matrix_runs_on_labels(job: dict[str, Any], value: Any) -> list[str]:
    """Resolve ``runs-on: ${{ matrix.<key> }}`` to the axis's values.

    Reads both ``strategy.matrix.<key>`` (the list axis) and any
    ``strategy.matrix.include[*].<key>`` entries, normalized to lowercase.
    """
    refs = [value] if isinstance(value, str) else (
        [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
    )
    keys = [m.group(1) for ref in refs if (m := _MATRIX_REF_RE.search(ref))]
    if not keys:
        return []
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return []
    out: list[str] = []
    for key in keys:
        axis = matrix.get(key)
        if isinstance(axis, list):
            out += [str(v).strip().lower() for v in axis
                    if isinstance(v, (str, int, float))]
        include = matrix.get("include")
        if isinstance(include, list):
            for entry in include:
                if isinstance(entry, dict) and isinstance(
                    entry.get(key), (str, int, float)
                ):
                    out.append(str(entry[key]).strip().lower())
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        runs_on = job.get("runs-on")
        labels = _runs_on_labels(runs_on) + _matrix_runs_on_labels(job, runs_on)
        for label in labels:
            note = _DEPRECATED_RUNNERS.get(label)
            if note is None:
                continue
            offenders.append(f"jobs.{job_id}: ``{label}`` ({note})")
            line = _line_of(job)
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
            break  # one offender per job is enough; don't double-report
    passed = not offenders
    desc = (
        "No job pins to an end-of-life hosted-runner image."
        if passed else
        f"{len(offenders)} job(s) pin to a deprecated GitHub-hosted "
        f"runner image: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. The image stops "
        f"receiving security patches and will eventually be "
        f"silently rerouted."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
