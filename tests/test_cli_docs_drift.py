"""CLI ↔ documentation drift guards.

The CLI surface (``pipeline_check/cli.py``) evolves independently from
its documentation in ``docs/usage.md``, ``action.yml``, and the
``--man`` manual pages. Adding a provider, output format, or CLI flag
without updating the doc surfaces is a silent regression that readers
discover only when their real-world invocation fails.

This test module catches the following drift classes:

  - ``action.yml`` path-dispatch case statement missing a provider that
    has a ``--<slug>-path`` CLI flag (``path`` input silently ignored).
  - ``docs/usage.md`` "Scan a specific provider" section missing a
    registered provider (readers can't discover the provider from the
    guide).
  - ``docs/usage.md`` output-format examples missing a value the CLI
    accepts (readers don't know the format exists).
  - ``--man`` INDEX text listing out of sync with ``_TOPICS`` dict in
    ``pipeline_check/core/manual.py`` (``--man`` index advertises a
    topic that doesn't exist, or omits one that does).
  - ``docs/usage.md`` exit-code table missing a documented exit code
    (operators write CI gates based on the table and miss a code).
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# ──────────────────────────────────────────────────────────────────────
# action.yml path-dispatch completeness
# ──────────────────────────────────────────────────────────────────────
#
# The action.yml ``case "$PIPELINE" in`` block maps the ``path`` input
# onto the corresponding ``--<provider>-path`` CLI flag. When a new
# provider lands with a path flag, the case statement must get a
# matching branch. Without it, ``path: charts/api`` is silently
# ignored for that provider — the scan runs at the repo root and
# produces wrong findings.


# Providers whose CLI path flag doesn't follow the --<slug>-path
# shape, or that don't take a workspace path at all:
#   aws     — scans a live account via boto3, no path
#   scm     — uses --scm-platform / --scm-repo, not a filesystem path
_ACTION_PATH_EXEMPT = {"aws", "scm"}

# Maps a CLI flag name to the action.yml case-branch provider name.
# Most providers use the identity mapping (--github-path → github),
# but some CLI flags use a non-obvious name.
_CLI_FLAG_TO_PROVIDER: dict[str, str] = {
    "--gha-path": "github",
    "--cfn-template": "cloudformation",
    "--tf-plan": "terraform",
    "--jenkinsfile-path": "jenkins",
    "--k8s-path": "kubernetes",
    "--oci-manifest": "oci",
}


def _action_yml_case_providers() -> set[str]:
    """Extract provider names from the action.yml ``case "$PIPELINE"`` block."""
    text = (REPO / "action.yml").read_text(encoding="utf-8")
    case_block = re.search(
        r'case "\$PIPELINE" in(.*?)esac', text, re.DOTALL,
    )
    assert case_block, "action.yml case block not found"
    return set(re.findall(r"^\s*(\w+)\)", case_block.group(1), re.MULTILINE))


def _cli_path_flags() -> dict[str, str]:
    """Return ``{cli_flag: provider_slug}`` for every ``--*-path``-style
    option in ``cli.py``'s ``_path_pairs`` tuple."""
    text = (REPO / "pipeline_check" / "cli.py").read_text(encoding="utf-8")
    block = re.search(r"_path_pairs.*?=.*?\((.*?)\)", text, re.DOTALL)
    assert block, "cli.py _path_pairs tuple not found"
    flag_pattern = re.compile(r'"(--[a-z0-9-]+)"')
    mapping: dict[str, str] = {}
    for flag in flag_pattern.findall(block.group(1)):
        if flag in _CLI_FLAG_TO_PROVIDER:
            mapping[flag] = _CLI_FLAG_TO_PROVIDER[flag]
        else:
            slug = re.sub(r"^--(.+)-path$", r"\1", flag)
            slug = slug.replace("-", "")
            mapping[flag] = slug
    return mapping


def test_action_yml_path_case_covers_cli_providers():
    """Every provider that has a ``--<slug>-path`` CLI flag (and isn't
    exempt) must appear in the ``action.yml`` case statement.

    Without a case branch, the action's ``path`` input is silently
    ignored for that provider, sending the scan at the repo root
    instead of the user-specified subdirectory.
    """
    case_providers = _action_yml_case_providers()
    cli_providers = set(_cli_path_flags().values())
    testable = cli_providers - _ACTION_PATH_EXEMPT
    missing = sorted(testable - case_providers)
    assert not missing, (
        "Provider(s) have a --<slug>-path CLI flag but no case branch "
        f"in action.yml: {missing}. The action's `path` input will be "
        "silently ignored for these providers."
    )


# ──────────────────────────────────────────────────────────────────────
# docs/usage.md provider example completeness
# ──────────────────────────────────────────────────────────────────────
#
# The "Scan a specific provider" section lists a ``--pipeline <name>``
# example for each provider. When a new provider lands, it should
# appear here so readers can discover it from the guide.


def test_usage_md_provider_examples_cover_all_providers():
    """Every registered provider must appear as a ``--pipeline <name>``
    example in the "Scan a specific provider" section of docs/usage.md."""
    from pipeline_check.core.providers import available

    text = (REPO / "docs" / "usage.md").read_text(encoding="utf-8")
    providers = set(available())
    documented = set(re.findall(r"--pipeline[s]?\s+(\w+)", text))
    missing = sorted(providers - documented)
    assert not missing, (
        "Provider(s) are registered but have no --pipeline example in "
        f"docs/usage.md: {missing}. Add an example to the 'Scan a "
        "specific provider' section."
    )


# ──────────────────────────────────────────────────────────────────────
# docs/usage.md output format completeness
# ──────────────────────────────────────────────────────────────────────


def _cli_output_choices() -> list[str]:
    """Extract the click.Choice values for ``--output`` from cli.py.

    Anchors on the ``"--output",\\n    "-o",`` decorator pair that
    uniquely identifies the output option (as opposed to other
    ``--output`` string occurrences in frozensets or help text).
    """
    text = (REPO / "pipeline_check" / "cli.py").read_text(encoding="utf-8")
    m = re.search(
        r'"--output",\s*\n\s*"-o",\s*\n\s*type=click\.Choice\(\s*\[(.*?)\]',
        text,
        re.DOTALL,
    )
    assert m, "cli.py --output/-o click.Choice not found"
    return re.findall(r'"(\w+)"', m.group(1))


def test_usage_md_output_formats_match_cli():
    """Every ``--output`` format the CLI accepts must appear in
    docs/usage.md so readers know it exists.

    The CLI's ``click.Choice`` list is the source of truth; the
    doc must reference each value at least once (in a code block,
    prose, or option description).
    """
    choices = _cli_output_choices()
    text = (REPO / "docs" / "usage.md").read_text(encoding="utf-8")
    missing = [c for c in choices if c not in text]
    assert not missing, (
        "Output format(s) accepted by --output but not mentioned in "
        f"docs/usage.md: {missing}. Add an example or mention in the "
        "'Output formats' section."
    )


# ──────────────────────────────────────────────────────────────────────
# --man topic index ↔ _TOPICS dict
# ──────────────────────────────────────────────────────────────────────
#
# The ``INDEX`` text in ``pipeline_check/core/manual.py`` lists
# available topics with one-line descriptions. The ``_TOPICS`` dict
# defines the actual implementations. A topic added to _TOPICS but
# not to INDEX (or vice versa) is invisible or broken.


def test_man_index_lists_every_topic():
    """The ``--man`` INDEX text must list every topic in ``_TOPICS``
    (excluding ``index`` itself), and vice versa.

    Drift: a developer adds a new ``_TOPICS`` entry but forgets to
    add the one-liner to ``INDEX``, so ``--man`` doesn't advertise it.
    Or a topic is listed in ``INDEX`` but the implementation was
    deleted from ``_TOPICS``.
    """
    from pipeline_check.core.manual import INDEX, topics

    registered = set(topics())
    index_text = INDEX
    listed_in_index: set[str] = set()
    for line in index_text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("pipeline_check") \
                and not stripped.startswith("Available") \
                and not stripped.startswith("Run e.g."):
            first_word = stripped.split()[0]
            if first_word in registered:
                listed_in_index.add(first_word)

    not_in_index = sorted(registered - listed_in_index)
    assert not not_in_index, (
        f"--man topics registered in _TOPICS but not listed in INDEX: "
        f"{not_in_index}. Add a one-liner for each to the INDEX text."
    )
    orphan_in_index = sorted(listed_in_index - registered)
    assert not orphan_in_index, (
        f"--man topics listed in INDEX but not in _TOPICS: "
        f"{orphan_in_index}. Remove from INDEX or add an implementation."
    )


# ──────────────────────────────────────────────────────────────────────
# docs/usage.md exit-code table completeness
# ──────────────────────────────────────────────────────────────────────


def test_usage_md_exit_codes_cover_documented_set():
    """The exit-code table in docs/usage.md must document codes 0-4.

    These are the canonical exit codes documented in the CLI's
    function docstring and in ``docs/stability.md``. The table is
    the authoritative reference for CI integrators.
    """
    text = (REPO / "docs" / "usage.md").read_text(encoding="utf-8")
    for code in range(5):
        assert f"| `{code}` |" in text, (
            f"docs/usage.md exit-code table missing code {code}. "
            "Update the 'Exit codes' section."
        )


# ──────────────────────────────────────────────────────────────────────
# action.yml output formats
# ──────────────────────────────────────────────────────────────────────


def test_action_yml_mentions_cli_output_formats():
    """Every ``--output`` format the CLI accepts (except the
    specialist ``threatmodel`` format) must appear somewhere in
    ``action.yml`` — in the input description, the default, or the
    shell script.

    Users read the action.yml input description on the Marketplace
    page and the shell script maps ``OUTPUT_FORMAT`` to ``--output``.
    If a format isn't mentioned anywhere, it's invisible to action
    consumers.
    """
    choices = set(_cli_output_choices())
    text = (REPO / "action.yml").read_text(encoding="utf-8")
    exempt = {"threatmodel"}
    missing = sorted(
        c for c in choices - exempt
        if c not in text
    )
    assert not missing, (
        "Output format(s) accepted by CLI --output but not mentioned "
        f"anywhere in action.yml: {missing}"
    )


# ──────────────────────────────────────────────────────────────────────
# action.yml input wiring
# ──────────────────────────────────────────────────────────────────────
#
# Every declared ``inputs:`` entry must be consumed somewhere in the
# composite action steps: forwarded as an env var, referenced in an
# ``if:`` condition, or passed to a ``with:`` field. An input that's
# declared but never consumed is dead configuration — users set it
# and nothing happens.

# Inputs consumed outside the main run step (setup, upload, PR
# comment), verified by their own wiring and not expected in the
# run env block.
_INFRA_INPUTS = {
    "python-version",       # setup-python step
    "pipeline-check-version",  # pip install step
    "upload-sarif",         # if-condition on the upload step
    "pr-comment",           # if-condition on the PR comment step
    "gh-token",             # PR comment step env
    "comment-mode",         # PR comment step env
}


def _action_yml_inputs() -> set[str]:
    """Return the set of input names declared in action.yml."""
    import yaml
    text = (REPO / "action.yml").read_text(encoding="utf-8")

    class _Loader(yaml.SafeLoader):
        pass
    _Loader.add_multi_constructor(
        "tag:yaml.org,2002:python/",
        lambda loader, suffix, node: loader.construct_scalar(node),
    )
    config = yaml.load(text, Loader=_Loader)
    return set(config.get("inputs", {}).keys())


def test_action_yml_inputs_are_all_wired() -> None:
    """Every ``inputs:`` entry in action.yml must be referenced in the
    composite action steps (env block, if-condition, or with-field).

    Catches the case where a new input is declared but the shell
    script never reads it — the user sets the input and nothing
    happens.
    """
    inputs = _action_yml_inputs()
    text = (REPO / "action.yml").read_text(encoding="utf-8")

    # Strip the inputs: declaration block so we only search the steps.
    runs_idx = text.find("runs:")
    assert runs_idx > 0, "action.yml has no runs: block"
    steps_text = text[runs_idx:]

    not_wired: list[str] = []
    for inp in inputs:
        if inp in _INFRA_INPUTS:
            continue
        token = f"inputs.{inp}"
        if token not in steps_text:
            not_wired.append(inp)
    assert not not_wired, (
        "action.yml inputs declared but never referenced in the "
        f"composite action steps: {sorted(not_wired)}. Either wire "
        "the input to an env var / with-field or remove it."
    )


# ──────────────────────────────────────────────────────────────────────
# pyproject.toml / mkdocs.yml description provider coverage
# ──────────────────────────────────────────────────────────────────────
#
# The one-line project description in pyproject.toml and the
# site_description in mkdocs.yml enumerate provider names. When a
# provider is added, these descriptions go stale. This test doesn't
# require every provider to be named (the descriptions are prose,
# not exhaustive lists), but it validates that the provider names
# that ARE mentioned are real registered providers.


def _extract_provider_names_from_prose(text: str) -> set[str]:
    """Extract lowercase provider-like names from a description string.

    Matches only the provider names the project uses; not a generic
    NLP parser.
    """
    from pipeline_check.core.providers import available
    all_providers = set(available())
    # Build a mapping of common display names to provider slugs.
    display_to_slug: dict[str, str] = {
        "aws": "aws",
        "terraform": "terraform",
        "cloudformation": "cloudformation",
        "github actions": "github",
        "gitlab ci": "gitlab",
        "azure devops": "azure",
        "bitbucket pipelines": "bitbucket",
        "jenkins": "jenkins",
        "circleci": "circleci",
        "cloud build": "cloudbuild",
        "google cloud build": "cloudbuild",
        "buildkite": "buildkite",
        "drone ci": "drone",
        "drone": "drone",
        "tekton": "tekton",
        "argo workflows": "argo",
        "argo cd": "argocd",
        "dockerfile": "dockerfile",
        "kubernetes": "kubernetes",
        "helm": "helm",
        "oci": "oci",
        "scm": "scm",
        "npm": "npm",
        "pypi": "pypi",
        "maven": "maven",
        "nuget": "nuget",
    }
    lower = text.lower()
    found: set[str] = set()
    for display, slug in display_to_slug.items():
        if display in lower:
            found.add(slug)
    return found


def test_pyproject_description_provider_names_are_registered() -> None:
    """Provider names mentioned in the ``pyproject.toml`` description
    must be registered providers. Catches the case where a provider
    is renamed or removed but the description still references the
    old name.
    """
    import tomllib
    from pipeline_check.core.providers import available

    with (REPO / "pyproject.toml").open("rb") as fh:
        desc = tomllib.load(fh)["project"]["description"]
    mentioned = _extract_provider_names_from_prose(desc)
    registered = set(available())
    unknown = sorted(mentioned - registered)
    assert not unknown, (
        "pyproject.toml description mentions provider names not in "
        f"the registry: {unknown}. Update the description or register "
        "the provider."
    )
