"""Provenance verification gate.

Shells out to the local supply-chain verifiers (``cosign``,
``slsa-verifier``, ``gh attestation``) to check that an artifact's
signature / SLSA provenance validates against an expected source
repository and signing identity. This turns the static "you should
sign" findings (GHA-100 and the attestation rules) into a runtime
"this artifact is verifiably built by who it claims" gate.

The engine is pure orchestration. It discovers which verifier binaries
are on ``PATH``, builds an injection-safe argv for each applicable
tool, runs it through an injectable runner (a real subprocess in
production, a fake in tests), and folds the per-tool outcomes into one
verdict:

    PASS          at least one tool ran and verified, and none failed
    FAIL          a tool ran and its verification failed
    INCONCLUSIVE  no selected tool could run (binary missing, or the
                  policy flags a tool needs were not supplied)

A missing binary degrades to INCONCLUSIVE, never a crash, mirroring the
``opa`` / ``helm`` shell-out pattern. A real verification failure is
FAIL so CI can gate on it. The verdict maps onto the canonical exit-code
contract: PASS -> 0, FAIL -> 1, INCONCLUSIVE -> 3.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Overall provenance result."""

    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


# Exit codes mirror the scan contract documented in ``docs/usage.md``:
# 0 verified, 1 verification failed (the gateable case), 3 could not
# verify (operational failure, like a missing verifier binary).
_EXIT_CODES: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FAIL: 1,
    Verdict.INCONCLUSIVE: 3,
}

#: Verifier binaries the gate knows how to drive, in the order they are
#: reported. ``"auto"`` (the CLI default) selects all of them.
KNOWN_TOOLS: tuple[str, ...] = ("cosign", "slsa-verifier", "gh")

#: Sentinel return code :func:`default_runner` uses for a subprocess that
#: exceeded its timeout. A timeout is an operational condition, not
#: evidence the artifact is bad, so it folds to INCONCLUSIVE not FAIL.
TIMEOUT_RETURNCODE = 124


class ProvenanceError(ValueError):
    """Raised when a verification policy is malformed before any tool runs."""


@dataclass(frozen=True, slots=True)
class VerifyPolicy:
    """What to verify and the identity it must validate against.

    ``ref`` is a canonical OCI image reference (no ``oci://`` prefix) or,
    when ``is_file`` is set, a local artifact path. The remaining fields
    are the verification policy each tool draws from; a tool that lacks
    the fields it needs is reported as "not applicable" rather than run.
    """

    ref: str
    is_file: bool = False
    source_uri: str | None = None
    builder_id: str | None = None
    certificate_identity: str | None = None
    certificate_identity_regexp: str | None = None
    certificate_oidc_issuer: str | None = None
    key: str | None = None
    owner: str | None = None
    provenance_path: str | None = None


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """Result of executing one verifier argv."""

    #: True when the binary existed and launched (a non-zero exit still
    #: counts as ``found``; only a missing / unspawnable binary is False).
    found: bool
    returncode: int
    stdout: str
    stderr: str


#: A runner takes a fully-resolved argv plus a timeout and returns the
#: outcome. Production uses :func:`default_runner`; tests inject a fake.
Runner = Callable[[Sequence[str], int], RunOutcome]


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Outcome for a single verifier within a run."""

    tool: str          # PATH binary name, e.g. "slsa-verifier"
    label: str         # human label, e.g. "slsa-verifier verify-image"
    available: bool    # binary found on PATH
    applicable: bool   # policy supplied the flags this tool needs
    ran: bool
    ok: bool
    returncode: int | None
    detail: str        # one-line summary (skip reason, pass, or failure)
    builder: str | None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "label": self.label,
            "available": self.available,
            "applicable": self.applicable,
            "ran": self.ran,
            "ok": self.ok,
            "returncode": self.returncode,
            "detail": self.detail,
            "builder": self.builder,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceReport:
    """Folded result across every selected verifier."""

    ref: str
    verdict: Verdict
    results: list[ToolResult]
    builder: str | None

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self.verdict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "verdict": self.verdict.value,
            "builder": self.builder,
            "exit_code": self.exit_code,
            "tools": [r.to_dict() for r in self.results],
        }


# ──────────────────────────────────────────────────────────────────────
# Per-tool argv builders. Each returns the args *after* the binary path,
# or ``None`` when the policy lacks the flags that tool requires.
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Invocation:
    label: str
    args: list[str]


def _cosign_plan(p: VerifyPolicy) -> _Invocation | None:
    # cosign verifies OCI signatures. Blob/file verification needs a
    # detached signature this generic policy doesn't model, so file
    # artifacts fall through to slsa-verifier / gh instead.
    if p.is_file:
        return None
    has_identity = bool(
        p.certificate_identity or p.certificate_identity_regexp
    )
    keyless = has_identity and bool(p.certificate_oidc_issuer)
    if not p.key and not keyless:
        return None
    args = ["verify"]
    if p.key:
        args += ["--key", p.key]
    if p.certificate_identity:
        args += ["--certificate-identity", p.certificate_identity]
    elif p.certificate_identity_regexp:
        args += ["--certificate-identity-regexp", p.certificate_identity_regexp]
    if p.certificate_oidc_issuer:
        args += ["--certificate-oidc-issuer", p.certificate_oidc_issuer]
    args.append(p.ref)
    return _Invocation("cosign verify", args)


def _slsa_plan(p: VerifyPolicy) -> _Invocation | None:
    # SLSA provenance verification is anchored on the source repository;
    # without an expected ``--source-uri`` there is nothing to verify.
    if not p.source_uri:
        return None
    if p.is_file:
        if not p.provenance_path:
            return None
        args = [
            "verify-artifact", p.ref,
            "--provenance-path", p.provenance_path,
            "--source-uri", p.source_uri,
        ]
        label = "slsa-verifier verify-artifact"
    else:
        args = ["verify-image", p.ref, "--source-uri", p.source_uri]
        label = "slsa-verifier verify-image"
    if p.builder_id:
        args += ["--builder-id", p.builder_id]
    return _Invocation(label, args)


def _gh_plan(p: VerifyPolicy) -> _Invocation | None:
    # ``gh attestation verify`` keys on the owner / repo that produced
    # the attestation; without it the command can't scope its lookup.
    if not p.owner:
        return None
    target = p.ref if p.is_file else f"oci://{p.ref}"
    return _Invocation(
        "gh attestation verify",
        ["attestation", "verify", target, "--owner", p.owner],
    )


_PLANNERS: dict[str, Callable[[VerifyPolicy], _Invocation | None]] = {
    "cosign": _cosign_plan,
    "slsa-verifier": _slsa_plan,
    "gh": _gh_plan,
}


def _not_applicable_reason(tool: str, p: VerifyPolicy) -> str:
    """A short why-skipped note for a tool the policy doesn't drive."""
    if tool == "cosign":
        if p.is_file:
            return "cosign verifies OCI refs; this target is a file"
        return (
            "needs --key, or --certificate-identity[-regexp] with "
            "--certificate-oidc-issuer"
        )
    if tool == "slsa-verifier":
        if p.source_uri and p.is_file:
            return "file verification needs --provenance"
        return "needs --source-uri"
    if tool == "gh":
        return "needs --owner"
    return "no policy supplied"


_BUILDER_TOKEN_SPLIT = re.compile(r"[\s\"'`]+")


def extract_builder(text: str) -> str | None:
    """Best-effort builder / source identity from verifier output.

    Looks for the first whitespace- or quote-delimited token that names a
    GitHub Actions workflow ref (``.../.github/workflows/x.yml@<ref>``),
    which is what ``slsa-verifier`` and ``cosign`` print for a verified
    build. Purely informational: it never affects the verdict.
    """
    for raw in _BUILDER_TOKEN_SPLIT.split(text):
        token = raw.strip().strip('.,()[]')
        if ".github/workflows/" in token and "@" in token:
            return token
    return None


def _validate(policy: VerifyPolicy) -> None:
    """Reject malformed / flag-smuggling policy values before any run.

    Every value is passed as its own argv element (no shell), so shell
    injection is impossible, but a value that starts with ``-`` could be
    misparsed by the verifier as an option. Reject leading-dash values
    and control characters up front, mirroring the helm ``--set`` guard.
    """
    if not policy.ref or not policy.ref.strip():
        raise ProvenanceError("artifact reference is empty")
    named = {
        "reference": policy.ref,
        "--source-uri": policy.source_uri,
        "--builder-id": policy.builder_id,
        "--certificate-identity": policy.certificate_identity,
        "--certificate-identity-regexp": policy.certificate_identity_regexp,
        "--certificate-oidc-issuer": policy.certificate_oidc_issuer,
        "--key": policy.key,
        "--owner": policy.owner,
        "--provenance": policy.provenance_path,
    }
    for name, value in named.items():
        if value is None:
            continue
        if any(c in value for c in ("\n", "\r", "\x00")):
            raise ProvenanceError(
                f"{name} value contains a control character"
            )
        if value.startswith("-"):
            raise ProvenanceError(
                f"{name} value {value!r} starts with '-'; refusing to "
                f"pass it as it could be parsed as a flag"
            )


def default_runner(argv: Sequence[str], timeout: int) -> RunOutcome:
    """Run a verifier argv as a subprocess, degrading on missing/slow tools."""
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return RunOutcome(found=False, returncode=127, stdout="", stderr="")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return RunOutcome(
            found=True,
            returncode=TIMEOUT_RETURNCODE,
            stdout=out,
            stderr=(err + f"\n[timed out after {timeout}s]").strip(),
        )
    except OSError as exc:
        return RunOutcome(found=False, returncode=126, stdout="", stderr=str(exc))
    return RunOutcome(
        found=True,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def verify_artifact(
    policy: VerifyPolicy,
    *,
    tools: Sequence[str] = KNOWN_TOOLS,
    timeout: int = 120,
    runner: Runner | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> ProvenanceReport:
    """Verify *policy* with each selected tool and fold the results.

    ``tools`` is the verifier selection (all of :data:`KNOWN_TOOLS` for
    the ``auto`` default, or a single name). ``which`` and ``runner`` are
    injected in tests to fake binary discovery and execution.
    """
    _validate(policy)
    run = runner or default_runner
    results: list[ToolResult] = []

    for tool in tools:
        planner = _PLANNERS.get(tool)
        if planner is None:
            raise ProvenanceError(f"unknown verifier {tool!r}")
        plan = planner(policy)
        binary = which(tool)
        available = binary is not None

        if plan is None:
            results.append(ToolResult(
                tool=tool, label=tool, available=available, applicable=False,
                ran=False, ok=False, returncode=None,
                detail=f"skipped: {_not_applicable_reason(tool, policy)}",
                builder=None,
            ))
            continue
        if not available:
            results.append(ToolResult(
                tool=tool, label=plan.label, available=False, applicable=True,
                ran=False, ok=False, returncode=None,
                detail=f"skipped: {tool} not found on PATH",
                builder=None,
            ))
            continue

        assert binary is not None  # narrowed by ``available``
        outcome = run([binary, *plan.args], timeout)
        if not outcome.found:
            results.append(ToolResult(
                tool=tool, label=plan.label, available=True, applicable=True,
                ran=False, ok=False, returncode=outcome.returncode,
                detail=f"skipped: {tool} could not be launched",
                builder=None, stderr=outcome.stderr,
            ))
            continue
        if outcome.returncode == TIMEOUT_RETURNCODE:
            # A timeout is operational, not a verification verdict; mark it
            # not-ran so it contributes to INCONCLUSIVE rather than FAIL.
            results.append(ToolResult(
                tool=tool, label=plan.label, available=True, applicable=True,
                ran=False, ok=False, returncode=outcome.returncode,
                detail=f"skipped: {tool} timed out",
                builder=None, stderr=outcome.stderr,
            ))
            continue

        ok = outcome.returncode == 0
        combined = f"{outcome.stdout}\n{outcome.stderr}"
        builder = extract_builder(combined) if ok else None
        if ok:
            detail = "verified"
        else:
            reason = _first_line(outcome.stderr) or _first_line(outcome.stdout)
            detail = f"verification failed: {reason}" if reason else "verification failed"
        results.append(ToolResult(
            tool=tool, label=plan.label, available=True, applicable=True,
            ran=True, ok=ok, returncode=outcome.returncode,
            detail=detail, builder=builder,
            stdout=outcome.stdout, stderr=outcome.stderr,
        ))

    verdict = _fold_verdict(results)
    builder = next(
        (r.builder for r in results if r.ran and r.ok and r.builder),
        None,
    )
    return ProvenanceReport(
        ref=policy.ref, verdict=verdict, results=results, builder=builder,
    )


def _fold_verdict(results: list[ToolResult]) -> Verdict:
    # A failure anywhere wins (safe default for a gate). Otherwise a PASS
    # requires at least one tool to have actually verified; a run where
    # nothing could run is inconclusive, not a pass.
    if any(r.ran and not r.ok for r in results):
        return Verdict.FAIL
    if any(r.ran and r.ok for r in results):
        return Verdict.PASS
    return Verdict.INCONCLUSIVE


__all__ = [
    "KNOWN_TOOLS",
    "TIMEOUT_RETURNCODE",
    "ProvenanceError",
    "ProvenanceReport",
    "RunOutcome",
    "Runner",
    "ToolResult",
    "Verdict",
    "VerifyPolicy",
    "default_runner",
    "extract_builder",
    "verify_artifact",
]
