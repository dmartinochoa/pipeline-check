"""GHA-067. ``actions/cache`` writes credential-shaped files.

zizmor proposal #723 (``cache-sensitive-files``). An
``actions/cache`` step (or the ``setup-*`` actions that wrap it
implicitly) whose ``path:`` covers a credential-shaped directory
publishes those credentials into the cache namespace. The
namespace is shared across PR builds: any contributor's PR run
can request a cache hit on the same key, restoring the same
content.

Sensitive paths the rule recognizes:

  * Whole-home dumps: ``~``, ``~/``, ``$HOME``.
  * Ecosystem credential stores: ``~/.docker``, ``~/.npmrc``,
    ``~/.aws``, ``~/.azure``, ``~/.gcloud``, ``~/.kube``,
    ``~/.gnupg``, ``~/.ssh``.
  * Build-tool credential stores: ``~/.gradle/gradle.properties``,
    ``~/.m2/settings.xml``, ``~/.netrc``.

The fix is to scope ``path:`` to the cacheable artifact only
(``~/.npm`` package metadata, not ``~/.npmrc``; ``~/.cache/pip``
download cache, not ``~/.config/pip``) and route credentials
through ``secrets:`` / environment variables that aren't cached.
"""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-067",
    title="``actions/cache`` writes credential-shaped paths",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-200", "CWE-524"),
    recommendation=(
        "Cache only the build artifacts that are actually cacheable. "
        "Don't cache ``~`` (the whole home dir), don't cache "
        "credential-shaped dotfiles (``~/.npmrc``, ``~/.docker``, "
        "``~/.aws``, ``~/.ssh``, ``~/.gnupg``, ``~/.netrc``, "
        "``~/.gradle/gradle.properties``, ``~/.m2/settings.xml``). "
        "Scope ``path:`` to the package-cache subdirectory only "
        "(``~/.cache/pip``, ``~/.npm``, ``~/.cargo/registry``) and "
        "let credentials live in the workflow's secrets context, "
        "never on disk in a path the cache restorer touches."
    ),
    docs_note=(
        "Fires when an ``actions/cache`` step's ``path:`` value "
        "(single line, multi-line YAML scalar block, or YAML list) "
        "contains any of the following:\n\n"
        "* The full home directory (``~``, ``~/``, ``$HOME``, "
        "``${HOME}``).\n"
        "* A credential-shaped dotfile or dotdir under the home "
        "directory: ``~/.npmrc``, ``~/.docker``, ``~/.aws``, "
        "``~/.azure``, ``~/.gcloud``, ``~/.kube``, ``~/.ssh``, "
        "``~/.gnupg``, ``~/.netrc``.\n"
        "* A build-tool config that carries credentials: "
        "``~/.gradle/gradle.properties``, ``~/.m2/settings.xml``.\n\n"
        "Pairs with GHA-052 (cache key derives from PR input) and "
        "GHA-011 (cache key untrusted). The triple "
        "(``cache-sensitive-files`` + ``cache-untrusted-key`` + "
        "``cache-poisoning-restore``) is the full cache-as-leak "
        "chain. Each rule fires independently so a workflow that "
        "carries any one leg gets the corresponding finding."
    ),
    known_fp=(
        "Self-hosted runners with carefully-scoped HOME directories "
        "where the credential-shaped paths are intentionally empty "
        "(initialized fresh per job). Suppress per-step via "
        "ignore-file when the runner provisioning model is "
        "documented. GitHub-hosted runners reset between jobs but "
        "the cache content persists across jobs / runs.",
    ),
    incident_refs=(
        "zizmor proposal #723 (cache-sensitive-files audit): "
        "https://github.com/zizmorcore/zizmor/issues/723",
    ),
    exploit_example=(
        "# Vulnerable: caches the whole home dir, which contains\n"
        "# the ``.npmrc`` the prior step seeded with the\n"
        "# publish token. Any contributor whose PR run hits the\n"
        "# same cache key restores the file.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          echo \"//registry.npmjs.org/:_authToken=${{ secrets."
        "NPM_TOKEN }}\" > ~/.npmrc\n"
        "          npm install\n"
        "      - uses: actions/cache@<sha>\n"
        "        with:\n"
        "          path: ~\n"
        "          key: home-${{ hashFiles('package-lock.json') }}\n"
        "\n"
        "# Safe: cache only the package metadata that's actually\n"
        "# reproducible from the lockfile, leave credentials out of\n"
        "# the cache namespace entirely.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          npm config set //registry.npmjs.org/:_authToken "
        "\"${{ secrets.NPM_TOKEN }}\"\n"
        "          npm install\n"
        "      - uses: actions/cache@<sha>\n"
        "        with:\n"
        "          path: ~/.npm\n"
        "          key: npm-${{ hashFiles('package-lock.json') }}"
    ),
)


_CACHE_USES_RE = re.compile(
    r"^actions/cache(?:/[^@]*)?(?:@.*)?$",
    re.IGNORECASE,
)

#: Path values that publish credentials into the cache namespace.
#: Compared after trimming whitespace and trailing slashes.
_SENSITIVE_PATHS: frozenset[str] = frozenset({
    # Whole-home dumps
    "~",
    "$HOME",
    "${HOME}",
    # Credential-shaped dotdirs (tilde prefix)
    "~/.docker",
    "~/.aws",
    "~/.azure",
    "~/.gcloud",
    "~/.kube",
    "~/.ssh",
    "~/.gnupg",
    # Credential-shaped dotdirs ($HOME prefix)
    "$HOME/.docker",
    "$HOME/.aws",
    "$HOME/.azure",
    "$HOME/.gcloud",
    "$HOME/.kube",
    "$HOME/.ssh",
    "$HOME/.gnupg",
    # Credential-shaped dotdirs (${HOME} prefix)
    "${HOME}/.docker",
    "${HOME}/.aws",
    "${HOME}/.azure",
    "${HOME}/.gcloud",
    "${HOME}/.kube",
    "${HOME}/.ssh",
    "${HOME}/.gnupg",
    # Credential-shaped dotfiles
    "~/.npmrc",
    "~/.netrc",
    "$HOME/.npmrc",
    "$HOME/.netrc",
    "${HOME}/.npmrc",
    "${HOME}/.netrc",
    # Build-tool credential stores
    "~/.gradle/gradle.properties",
    "~/.m2/settings.xml",
    "$HOME/.gradle/gradle.properties",
    "$HOME/.m2/settings.xml",
    "${HOME}/.gradle/gradle.properties",
    "${HOME}/.m2/settings.xml",
})


def _normalize_path(path_line: str) -> str:
    """Strip whitespace and a trailing slash for sensitive-path lookup."""
    line = path_line.strip()
    if line.endswith("/") and len(line) > 1:
        line = line[:-1]
    return line


def _scan_cache_path(value: Any) -> list[str]:
    """Return sensitive offender paths from a cache ``path:`` value.

    ``actions/cache`` accepts a string (single path or block scalar
    with newlines) or a list. Both shapes get flattened to a
    per-entry list before normalization.
    """
    if isinstance(value, str):
        lines = value.splitlines() if "\n" in value else [value]
    elif isinstance(value, list):
        lines = [str(v) for v in value]
    else:
        return []
    out: list[str] = []
    for line in lines:
        normalized = _normalize_path(line)
        if not normalized:
            continue
        if normalized in _SENSITIVE_PATHS:
            out.append(normalized)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if not isinstance(uses, str) or not _CACHE_USES_RE.match(uses):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            offenders_here = _scan_cache_path(with_block.get("path"))
            if not offenders_here:
                continue
            offenders.append(
                f"{job_id}[{idx}]: {', '.join(offenders_here)}"
            )
            line = _line_of(step)
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
    passed = not offenders
    desc = (
        "No ``actions/cache`` step caches credential-shaped paths."
        if passed else
        f"{len(offenders)} ``actions/cache`` step(s) publish "
        f"credential-shaped paths into the (PR-readable) cache "
        f"namespace: {'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. Restrict the "
        f"path to the package-metadata subdirectory and route "
        f"credentials through secrets / env, not on-disk dotfiles."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
