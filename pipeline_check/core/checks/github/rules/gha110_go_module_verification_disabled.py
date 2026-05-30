"""GHA-110. Workflow disables Go module checksum / sum-db verification."""
from __future__ import annotations

from typing import Any

from ..._primitives.go_insecure_env import (
    insecure_settings_in_env,
    insecure_settings_in_script,
)
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-110",
    title="Workflow disables Go module checksum / sum-db verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-353", "CWE-494"),
    recommendation=(
        "Remove the Go toolchain environment settings that turn off "
        "module integrity verification, so ``go build`` keeps "
        "checking every downloaded module against ``go.sum`` and the "
        "checksum transparency database. Specifically: drop "
        "``GOFLAGS=-insecure`` (it fetches modules over plain HTTP "
        "with TLS validation off), ``GOSUMDB=off`` and legacy "
        "``GONOSUMCHECK`` (they disable the checksum DB / sum check), "
        "and any ``GOINSECURE`` entry; and scope ``GOPRIVATE`` / "
        "``GONOSUMDB`` to the exact internal namespace that needs it "
        "(``corp.example.com/team/*``) instead of a broad ``*`` or a "
        "whole public host. This is the CI-env twin of GOMOD-001: "
        "committing a ``go.sum`` doesn't help if the runner is "
        "configured to ignore it. For private modules, prefer a "
        "trusted internal proxy (``GOPROXY``) that still enforces "
        "checksums over disabling verification."
    ),
    docs_note=(
        "Walks the workflow / job / step ``env:`` blocks and every "
        "``run:`` step (for inline ``export GOSUMDB=off`` / "
        "``GOFLAGS=-insecure go build`` assignments) and flags the "
        "Go integrity-disabling settings via the shared "
        "``_primitives/go_insecure_env`` detector: ``GOFLAGS`` with "
        "``-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any "
        "``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` "
        "glob (``*`` / public TLD / whole host).\n\n"
        "Scoped ``GOPRIVATE`` (an internal org namespace) and "
        "``GOPROXY=off`` / ``GOPROXY=direct`` (still checksum-"
        "verified) are not flagged. The env-var face of the "
        "verification-bypass surface GOMOD-001 warns about; shipped "
        "here (and in GL-037 / CC-033) rather than the gomod loader "
        "because the setting lives in the CI config, not ``go.mod``."
    ),
    known_fp=(
        "A workflow that builds only against an internal module "
        "proxy on a trusted network may set a scoped ``GOINSECURE`` "
        "for one internal host deliberately. Suppress per workflow "
        "with a rationale naming the host; the safer path is a "
        "TLS-terminating internal proxy that preserves checksum "
        "verification.",
    ),
    incident_refs=(
        "Verification-bypass class: a runner told to skip the Go "
        "checksum database / sum file can be served a substituted "
        "module (a MITM on an insecure fetch, a poisoned proxy) "
        "without ``go mod verify`` catching it, the same gap "
        "GOMOD-001 flags from the ``go.sum`` side."
    ),
    exploit_example=(
        "# Vulnerable: the workflow disables module verification.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      GOSUMDB: \"off\"\n"
        "      GOFLAGS: -insecure\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: go build ./...\n"
        "\n"
        "# Attack: with GOSUMDB off and -insecure, `go build` fetches\n"
        "# modules over plain HTTP and skips the checksum DB. A MITM\n"
        "# (or a poisoned mirror) serves a backdoored module; nothing\n"
        "# verifies it against go.sum, so the build links the\n"
        "# substitute.\n"
        "\n"
        "# Safe: drop the toggles; let go.sum + the sum DB verify.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
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

    _record("workflow env", insecure_settings_in_env(doc.get("env")))
    for job_id, job in iter_jobs(doc):
        _record(f"{job_id} env", insecure_settings_in_env(job.get("env")))
        for step in iter_steps(job):
            _record(f"{job_id} step env", insecure_settings_in_env(step.get("env")))
            run = step.get("run")
            if isinstance(run, str):
                _record(f"{job_id} run", insecure_settings_in_script(run))
    passed = not offenders
    desc = (
        "No Go module-verification-disabling settings in the workflow."
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
