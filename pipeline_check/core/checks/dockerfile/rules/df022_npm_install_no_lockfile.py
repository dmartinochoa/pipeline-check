"""DF-022, ``RUN npm install`` used in image builds instead of ``npm ci``."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-022",
    title="RUN uses npm install instead of npm ci",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Switch to ``npm ci`` (or ``yarn install --frozen-lockfile`` / "
        "``pnpm install --frozen-lockfile`` for those toolchains). "
        "``npm ci`` requires a ``package-lock.json`` and fails the "
        "build if it disagrees with ``package.json``; it never "
        "rewrites the lockfile and never installs packages outside "
        "the locked set. ``npm install`` does the opposite: it "
        "resolves ranges in ``package.json`` at build time and "
        "happily mutates the lockfile to fit the resolution, so a "
        "transient dependency the team never reviewed can land in "
        "the image."
    ),
    docs_note=(
        "Mirrors GHA-022 / GL-022 / JF-021 (CI-side lockfile "
        "integrity) at the image-build layer. The build-time consequence "
        "is the same shape: dependency resolution happens against "
        "the live registry rather than against the committed "
        "lockfile, so the image ends up carrying whatever the "
        "registry served at build time rather than the set the team "
        "audited. The rule fires on bare ``npm install`` / ``npm i`` "
        "as well as on flagged variants (``--no-package-lock``, "
        "``--force``, ``--legacy-peer-deps``) which all defeat the "
        "lockfile contract one way or another."
    ),
    known_fp=(
        "Multi-stage build whose runtime image copies in a pre-"
        "computed ``node_modules`` and never installs at build time "
        "is unaffected, the rule only fires on directives that "
        "actually invoke ``npm install``.",
        "``npm install --production`` is still flagged: it ignores "
        "``devDependencies`` but still re-resolves and mutates the "
        "lockfile. Use ``npm ci --omit=dev`` instead.",
    ),
    exploit_example=(
        "# Vulnerable: the image build resolves dependencies\n"
        "# against the live registry instead of the committed\n"
        "# lockfile.\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm install\n"
        "\n"
        "# Attack: `npm install` re-resolves the `^` / `~` ranges\n"
        "# in package.json at build time and rewrites\n"
        "# package-lock.json to match, so the committed lockfile\n"
        "# is advisory, not binding. A transitive dependency\n"
        "# ships a fresh malicious patch release (the\n"
        "# event-stream / Shai-Hulud shape); the next rebuild\n"
        "# pulls it even though no reviewed change touched the\n"
        "# repo, and bakes its install script into the image.\n"
        "\n"
        "# Safe: `npm ci` installs exactly the locked set and\n"
        "# fails the build if package.json and the lockfile\n"
        "# disagree. It never mutates the lockfile or reaches\n"
        "# past it.\n"
        "COPY package.json package-lock.json ./\n"
        "RUN npm ci"
    ),
)


# ``npm install`` shapes that defeat the lockfile contract. The
# explicit ``ci`` subcommand is the safe one; anything else with the
# ``install`` verb (or its ``i`` alias) is flagged. ``npm i -g <tool>``
# global installs are *not* flagged here, those install ad-hoc CLI tools
# (``npm i -g cdk``) and don't pretend to be reproducible.
_NPM_INSTALL_RE = re.compile(
    r"\bnpm\s+(?:install|i)\b"
    r"(?!\s+-g\b)"        # not ``npm i -g foo``
    r"(?!\s+--global\b)",  # not ``npm install --global foo``
    re.IGNORECASE,
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        for m in _NPM_INSTALL_RE.finditer(body):
            offenders.append(f"L{line_no}: {m.group(0).strip()}")
            locations.append(Location(
                path=df.path, start_line=line_no, end_line=line_no,
            ))
            break
    passed = not offenders
    desc = (
        "No ``RUN`` body uses ``npm install`` (``npm ci`` is the safe "
        "reproducible-build invocation)."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies use ``npm install`` "
        f"instead of ``npm ci``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Dependency resolution "
        f"runs against the live registry at build time, so the image "
        f"can carry packages the lockfile never recorded."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
