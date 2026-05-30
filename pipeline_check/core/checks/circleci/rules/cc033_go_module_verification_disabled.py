"""CC-033. Job disables Go module checksum / sum-db verification."""
from __future__ import annotations

from typing import Any

from ..._primitives.go_insecure_env import (
    insecure_settings_in_env,
    insecure_settings_in_script,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands, iter_steps

RULE = Rule(
    id="CC-033",
    title="Job disables Go module checksum / sum-db verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-353", "CWE-494"),
    recommendation=(
        "Remove the Go toolchain environment settings that turn off "
        "module integrity verification so ``go build`` keeps "
        "checking every downloaded module against ``go.sum`` and the "
        "checksum transparency database. Drop ``GOFLAGS=-insecure`` "
        "(plain HTTP fetch, TLS off), ``GOSUMDB=off`` / legacy "
        "``GONOSUMCHECK`` (checksum DB / sum check off), and any "
        "``GOINSECURE``; scope ``GOPRIVATE`` / ``GONOSUMDB`` to the "
        "exact internal namespace (``corp.example.com/team/*``) "
        "rather than a broad ``*`` or whole public host. This is the "
        "CI-env twin of GOMOD-001, a committed ``go.sum`` is moot if "
        "the runner ignores it. For private modules, prefer a "
        "trusted internal ``GOPROXY`` that still enforces checksums "
        "over disabling verification."
    ),
    docs_note=(
        "Walks each job's ``environment:`` map, every ``run`` step's "
        "``environment:`` map, and every ``run`` command body (for "
        "inline ``export GOSUMDB=off`` assignments), and flags the Go "
        "integrity-disabling settings via the shared "
        "``_primitives/go_insecure_env`` detector: ``GOFLAGS`` with "
        "``-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any "
        "``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` "
        "glob.\n\n"
        "Scoped ``GOPRIVATE`` and ``GOPROXY=off`` / ``direct`` (still "
        "checksum-verified) are not flagged. The CircleCI sibling of "
        "GHA-110 / GL-037, the CI-env face of the verification-"
        "bypass surface GOMOD-001 warns about."
    ),
    known_fp=(
        "A job that builds only against an internal module proxy on "
        "a trusted network may set a scoped ``GOINSECURE`` for one "
        "internal host deliberately. Suppress per job with a "
        "rationale; a TLS-terminating internal proxy that preserves "
        "checksum verification is the safer path.",
    ),
    incident_refs=(
        "Verification-bypass class: a runner told to skip the Go "
        "checksum database / sum file can be served a substituted "
        "module without ``go mod verify`` catching it, the same gap "
        "GOMOD-001 flags from the ``go.sum`` side.",
    ),
    exploit_example=(
        "# Vulnerable: the job disables module verification.\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: cimg/go:1.22\n"
        "    environment:\n"
        "      GOSUMDB: \"off\"\n"
        "      GOFLAGS: -insecure\n"
        "    steps:\n"
        "      - checkout\n"
        "      - run: go build ./...\n"
        "\n"
        "# Attack: with GOSUMDB off and -insecure, the runner fetches\n"
        "# modules over plain HTTP and skips the checksum DB; a MITM\n"
        "# or poisoned mirror serves a backdoored module and nothing\n"
        "# verifies it against go.sum.\n"
        "\n"
        "# Safe: drop the toggles; let go.sum + the sum DB verify.\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: cimg/go:1.22\n"
        "    steps:\n"
        "      - checkout\n"
        "      - run: go build ./...\n"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    seen: set[str] = set()

    def _record(scope: str, labels: list[str]) -> None:
        for label in labels:
            key = f"{scope}|{label}"
            if key in seen:
                continue
            seen.add(key)
            offenders.append(f"{scope}: {label}")

    for job_id, job in iter_jobs(doc):
        _record(f"{job_id} environment", insecure_settings_in_env(job.get("environment")))
        for step in iter_steps(job):
            if isinstance(step, dict):
                run = step.get("run")
                if isinstance(run, dict):
                    _record(
                        f"{job_id} run environment",
                        insecure_settings_in_env(run.get("environment")),
                    )
        for cmd in iter_run_commands(job):
            _record(f"{job_id} run", insecure_settings_in_script(cmd))
    passed = not offenders
    desc = (
        "No Go module-verification-disabling settings in the config."
        if passed else
        f"{len(offenders)} Go integrity-disabling setting(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The runner can no "
        f"longer prove a downloaded module matches go.sum / the "
        f"checksum database."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
