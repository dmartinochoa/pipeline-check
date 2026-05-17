"""DF-024, ``RUN npm install`` runs lifecycle scripts (no ``--ignore-scripts``)."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-024",
    title="RUN npm/yarn/pnpm install runs lifecycle scripts",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Pass ``--ignore-scripts`` to every ``npm`` / ``npm ci`` / "
        "``pnpm install`` / ``yarn install`` invocation in the "
        "Dockerfile, or set ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` / "
        "``ENV YARN_ENABLE_SCRIPTS=false`` before the install line. "
        "Lifecycle scripts (``preinstall``, ``install``, ``postinstall``, "
        "``prepare``) are the blast radius of the Shai-Hulud / TanStack / "
        "axios incidents, a single compromised dependency in the "
        "transitive tree runs arbitrary code with the build container's "
        "credentials. ``--ignore-scripts`` removes that primitive without "
        "affecting lockfile resolution; the few legitimate consumers "
        "(``node-gyp``-based native modules) should be allow-listed via "
        "a follow-up ``npm rebuild <pkg> --ignore-scripts=false`` line "
        "scoped to the specific package."
    ),
    docs_note=(
        "Fires on ``npm install`` / ``npm ci`` / ``npm i`` (non-global), "
        "``pnpm install`` / ``pnpm i``, and ``yarn install`` / bare "
        "``yarn`` in a ``RUN`` body when ``--ignore-scripts`` is absent "
        "from the same line. Detection short-circuits when the same "
        "Dockerfile sets ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` "
        "(``npm``), ``ENV YARN_ENABLE_SCRIPTS=false`` (yarn berry), or "
        "``ENV CI=true`` is paired with an ``.npmrc`` configured to "
        "disable scripts (the env-level kill-switch is detected; the "
        "rule trusts ``.npmrc`` only when it's also written by the "
        "Dockerfile via ``echo ignore-scripts=true >> .npmrc``). "
        "Complements DF-022 (``npm ci`` vs ``npm install``), which "
        "guards lockfile integrity; DF-024 guards lifecycle-script "
        "execution. A pinned lockfile does not help when the pinned "
        "version is the malicious one, only ``--ignore-scripts`` does."
    ),
    known_fp=(
        "Images that build native modules via ``node-gyp`` need the "
        "lifecycle scripts to compile bindings (``better-sqlite3``, "
        "``sharp``, ``canvas``, ...). The fix is per-package: keep the "
        "top-level install on ``--ignore-scripts``, then ``RUN npm "
        "rebuild better-sqlite3`` afterward, scoped to the audited "
        "package. Suppress with a one-line rationale only when an "
        "engineer has confirmed every script-running dep is "
        "first-party or pinned to a hash.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (2026): postinstall scripts in compromised "
        "packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, used "
        "the stolen tokens to publish more compromised packages and "
        "push malicious workflow files into victim repos. "
        "``--ignore-scripts`` neutralizes the postinstall primitive at "
        "install time.",
        "TanStack / Mistral npm compromise (May 2026): 84 versions "
        "across 42 packages published in minutes, each carrying a "
        "credential-stealing ``postinstall``. Lockfile pinning did not "
        "help (the pinned tag itself was poisoned); ``--ignore-scripts`` "
        "would have stopped execution.",
    ),
    exploit_example=(
        "# Vulnerable: postinstall in a transitive dep runs with the\n"
        "# builder's environment (NPM_TOKEN, GH_TOKEN, AWS_*).\n"
        "FROM node:20@sha256:<digest>\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci          # <-- runs postinstall of every dep\n"
        "\n"
        "# Attack: the compromised package's package.json carries:\n"
        "#   \"scripts\": { \"postinstall\": \"node ./harvest.js\" }\n"
        "# harvest.js reads ~/.npmrc, process.env, ~/.aws/credentials\n"
        "# and POSTs them to a webhook. The image is also tampered:\n"
        "# the script writes a second-stage loader into node_modules\n"
        "# that runs at every container start.\n"
        "\n"
        "# Safe: scripts disabled at install time; rebuild only the\n"
        "# audited native-module set afterward.\n"
        "FROM node:20@sha256:<digest>\n"
        "ENV NPM_CONFIG_IGNORE_SCRIPTS=true\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci --ignore-scripts\n"
        "RUN npm rebuild better-sqlite3 sharp    # audited allowlist"
    ),
)


# ``npm install`` / ``npm ci`` / ``npm i`` (not global), ``pnpm
# install`` / ``pnpm i``, ``yarn install``, and bare ``yarn``
# (the default yarn 1.x behavior is ``install``).
_INSTALL_RE = re.compile(
    r"\b(?:"
    r"npm\s+(?:install|ci|i)(?!\s+-g\b)(?!\s+--global\b)"
    r"|pnpm\s+(?:install|i)(?!\s+-g\b)(?!\s+--global\b)"
    r"|yarn(?:\s+install)?\b"
    r")",
    re.IGNORECASE,
)
_IGNORE_SCRIPTS_RE = re.compile(r"--ignore-scripts\b", re.IGNORECASE)


def _env_disables_scripts(df: Dockerfile) -> bool:
    """True when an ``ENV`` line turns off lifecycle scripts image-wide.

    Both spellings are accepted: npm's ``NPM_CONFIG_IGNORE_SCRIPTS``
    (any truthy literal: ``true``, ``1``, ``yes``) and yarn berry's
    ``YARN_ENABLE_SCRIPTS=false``. A repository that bakes one of these
    into the image has opted into the safe default and shouldn't be
    flagged on every ``RUN npm ci`` line; rely on the env block.
    """
    for ins in df.instructions:
        if ins.directive != "ENV":
            continue
        body = ins.args
        if re.search(
            r"\bNPM_CONFIG_IGNORE_SCRIPTS\s*=\s*[\"']?(?:true|1|yes)\b",
            body, re.IGNORECASE,
        ):
            return True
        if re.search(
            r"\bYARN_ENABLE_SCRIPTS\s*=\s*[\"']?(?:false|0|no)\b",
            body, re.IGNORECASE,
        ):
            return True
    return False


def check(df: Dockerfile) -> Finding:
    if _env_disables_scripts(df):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=df.path,
            description=(
                "Lifecycle scripts disabled image-wide via "
                "``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` / "
                "``ENV YARN_ENABLE_SCRIPTS=false``."
            ),
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        if not _INSTALL_RE.search(body):
            continue
        if _IGNORE_SCRIPTS_RE.search(body):
            continue
        # Capture the matched install verb so the description points
        # at the actual offender rather than a generic "npm" string.
        verb = _INSTALL_RE.search(body)
        label = verb.group(0).strip() if verb else "install"
        offenders.append(f"L{line_no}: {label}")
        locations.append(Location(
            path=df.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every npm / yarn / pnpm install in this Dockerfile passes "
        "``--ignore-scripts`` or runs under an image-wide kill-switch."
        if passed else
        f"{len(offenders)} install line(s) run lifecycle scripts: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromised package "
        f"anywhere in the transitive tree runs code with the builder's "
        f"environment (Shai-Hulud / TanStack pattern)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
