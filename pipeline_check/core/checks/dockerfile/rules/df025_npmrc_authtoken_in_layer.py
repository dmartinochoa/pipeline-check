"""DF-025, ``RUN`` writes an npm/pip auth token into a Docker layer."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-025",
    title="RUN writes a registry auth token into a Docker layer",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-3"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522", "CWE-538"),
    recommendation=(
        "Don't bake registry tokens into layers. Use BuildKit secret "
        "mounts: ``RUN --mount=type=secret,id=npm,target=/root/.npmrc "
        "npm ci`` (the file is mounted only for the duration of the "
        "step and never lands in the image). For pip, mount a "
        "``pip.conf`` the same way, or use ``--mount=type=secret`` to "
        "expose ``PIP_INDEX_URL`` containing the credentials. A "
        "secret written into a layer is recoverable from the image "
        "with ``docker save`` + ``tar``, even if a later ``RUN`` "
        "deletes the file."
    ),
    docs_note=(
        "Fires when a ``RUN`` body writes a recognized registry-auth "
        "token line into a file via ``echo`` / ``printf`` / heredoc. "
        "Patterns matched: ``//registry.npmjs.org/:_authToken=`` (and "
        "any ``//host/:_authToken=`` shape), ``//host/:_password=``, "
        "``//host/:_auth=`` (npm legacy basic auth), and the pip "
        "equivalents ``index-url = https://<user>:<pass>@host`` and "
        "``extra-index-url = https://<user>:<pass>@host``. Token value "
        "may be a literal or a ``$VAR`` / ``${VAR}`` interpolation, "
        "both end up in the layer once the build args / env are "
        "substituted. Complements DF-019 (``COPY`` of a ``.npmrc`` "
        "from the build context); DF-025 catches the in-layer write "
        "that DF-019 can't see."
    ),
    known_fp=(
        "An interpolation that references an env var the Dockerfile "
        "intentionally leaves unset at build time (placeholder line "
        "for a templated install script) still triggers the rule; the "
        "regex can't reason about whether ``$NPM_TOKEN`` resolves to "
        "anything. Either remove the line entirely or move to a "
        "``--mount=type=secret`` flow.",
    ),
    incident_refs=(
        "Numerous public Docker Hub leaks of ``_authToken=`` lines in "
        "image layers (search ``//registry.npmjs.org/:_authToken`` on "
        "public registries). The same lateral-movement primitive the "
        "Shai-Hulud worm relies on: any stolen NPM token reaches the "
        "victim's publish-scope packages on the next ``npm publish``.",
    ),
    exploit_example=(
        "# Vulnerable: token interpolated from a build ARG and written\n"
        "# into a layer. The arg value is recoverable by anyone with\n"
        "# image pull access (and from public image scans).\n"
        "FROM node:20@sha256:<digest>\n"
        "ARG NPM_TOKEN\n"
        "RUN echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" \\\n"
        "    > /root/.npmrc \\\n"
        "    && npm ci\n"
        "\n"
        "# Attack: docker save image | tar xO --wildcards '*.npmrc'\n"
        "# yields the literal token. The attacker then publishes a\n"
        "# new patch version of one of the org's packages with a\n"
        "# postinstall stealer (Shai-Hulud shape).\n"
        "\n"
        "# Safe: BuildKit secret mount. The .npmrc is mounted into\n"
        "# the step's filesystem, used by npm ci, then unmounted; the\n"
        "# layer carries no trace of the token.\n"
        "FROM node:20@sha256:<digest>\n"
        "RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \\\n"
        "    npm ci --ignore-scripts"
    ),
)


# ``//registry.npmjs.org/:_authToken=...`` is the canonical npm auth
# line. Match any host (``//<host>/``) and any of the three credential
# keys npm accepts (``_authToken``, ``_password``, ``_auth``). The
# value is allowed to be a literal or a ``$VAR`` / ``${VAR}`` shell
# interpolation; both end up in the layer once the shell expands.
_NPM_AUTHLINE_RE = re.compile(
    r"//[\w.\-]+/:\s*_(?:authToken|password|auth)\s*=\s*\S+",
    re.IGNORECASE,
)

# Pip equivalents: ``index-url = https://<user>:<pass>@host`` /
# ``extra-index-url = https://<user>:<pass>@host``. The ``@`` after a
# colon-separated credential pair is the recoverable artifact.
_PIP_CREDLINE_RE = re.compile(
    r"(?:extra-)?index-url\s*=?\s*https?://[^\s/@:]+:[^\s/@]+@[\w.\-]+",
    re.IGNORECASE,
)

# Restrict the search to ``RUN`` bodies that actually write a file.
# A bare ``echo //registry.npmjs.org/:_authToken=...`` printed to
# stdout (no redirect) doesn't persist into a layer; the rule cares
# only about the redirect-to-file form.
_FILE_WRITE_RE = re.compile(
    r"(?:>>?|tee(?:\s+-a)?\s+\S+|cat\s*<<-?\s*['\"]?\w+['\"]?)",
    re.IGNORECASE,
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        if not _FILE_WRITE_RE.search(body):
            continue
        if _NPM_AUTHLINE_RE.search(body):
            offenders.append(f"L{line_no}: npm auth line written to layer")
        elif _PIP_CREDLINE_RE.search(body):
            offenders.append(f"L{line_no}: pip credentials in index URL")
        else:
            continue
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No ``RUN`` body writes a registry auth token into a layer."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies write a registry "
        f"credential into a layer: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anything in a layer is "
        f"recoverable from a pulled image; use a BuildKit secret mount "
        f"(``--mount=type=secret``) instead."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
