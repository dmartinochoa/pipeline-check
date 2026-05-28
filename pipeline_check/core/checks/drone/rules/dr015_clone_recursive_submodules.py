"""DR-015. Pipeline clone block enables recursive submodule cloning."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline

RULE = Rule(
    id="DR-015",
    title="Pipeline clone enables recursive submodule cloning",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Disable recursive submodule cloning at the pipeline "
        "level. Three remediation patterns:\n\n"
        "* For repos that don't use submodules:\n\n"
        "    clone:\n"
        "      disable: false\n"
        "      depth: 50\n\n"
        "* For repos that use submodules but pin them at known "
        "commit SHAs:\n\n"
        "    clone:\n"
        "      disable: false\n"
        "      recursive: false   # default; clone submodules explicitly per-step\n\n"
        "* For repos that genuinely need recursive submodules at "
        "clone time, restrict via a custom clone step that "
        "verifies the submodule URLs against an allowlist before "
        "``git submodule update --init --recursive``.\n\n"
        "Recursive submodule cloning pulls every "
        "``.gitmodules``-declared dependency at clone time, "
        "before any step has a chance to audit the pulled "
        "content. If a contributor adds a malicious "
        "``.gitmodules`` entry pointing at an attacker-"
        "controlled URL, the pull happens with the runner's "
        "filesystem privileges. The fetched content can include "
        "``.gitattributes`` with filter-driven shell hooks that "
        "execute at clone time on Drone's runner."
    ),
    docs_note=(
        "Reads ``pipeline.clone.recursive`` and fires when set "
        "to ``true``. The default Drone clone behavior "
        "(``disable: false`` + ``recursive`` absent) is "
        "single-level: the top-level repo only, no submodules. "
        "Explicit ``recursive: true`` opts into the failure "
        "mode the rule catches.\n\n"
        "Drone's clone plugin runs before any pipeline step, "
        "so a malicious ``.gitmodules`` lands content on the "
        "runner before any user-defined verification can run. "
        "Disabling recursive cloning at the pipeline level "
        "moves the submodule fetch to an explicit step where "
        "URL allowlists and content verification are "
        "possible."
    ),
    known_fp=(
        "Some monorepo layouts use submodules for shared "
        "internal code where the URLs are known-good "
        "(github.com/<myorg>/<known-sibling>) and the "
        "convenience of recursive cloning outweighs the "
        "marginal risk. Suppress per pipeline with a one-line "
        "rationale naming the trust boundary of the "
        "submodule URLs.",
    ),
    incident_refs=(
        "Pattern of `.gitattributes`-driven shell hooks "
        "executing during recursive clone on CI runners. "
        "Documented attacker primitive in git's CVE history "
        "(CVE-2017-1000117 et al.). Recursive submodule clone "
        "amplifies the surface by pulling content from every "
        "URL in the dependency graph, not just the top-level "
        "repo.",
    ),
    exploit_example=(
        "# Vulnerable: recursive submodule clone enabled.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "clone:\n"
        "  recursive: true\n"
        "steps:\n"
        "  - name: build\n"
        "    image: alpine:3.19@sha256:abc...\n"
        "    commands: [./build.sh]\n"
        "\n"
        "# Attack: a contributor modifies .gitmodules to add a\n"
        "# submodule pointing at an attacker-controlled repo.\n"
        "# Drone's clone plugin pulls the submodule recursively\n"
        "# before any step runs; the submodule's\n"
        "# .gitattributes carries a filter-driven shell hook\n"
        "# that executes on the runner with the clone plugin's\n"
        "# privileges.\n"
        "\n"
        "# Safe: disable recursive at the pipeline level; opt in\n"
        "# explicitly per step with URL allowlist.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "clone:\n"
        "  recursive: false\n"
        "steps:\n"
        "  - name: clone-allowlisted-submodules\n"
        "    image: alpine/git:2.40@sha256:def...\n"
        "    commands:\n"
        "      - git submodule status\n"
        "      # Verify each submodule URL before fetching.\n"
        "      - test \"$(git config --get submodule.lib.url)\" \\\n"
        "          = \"https://github.com/myorg/lib\"\n"
        "      - git submodule update --init lib\n"
    ),
)


def check(pipeline: Pipeline) -> Finding:
    clone = pipeline.data.get("clone")
    name = pipeline.data.get("name", f"doc[{pipeline.doc_index}]")
    if not isinstance(clone, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline {name!r} uses the default clone "
                f"(non-recursive)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    recursive = clone.get("recursive")
    if recursive is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline {name!r} clone.recursive is "
                f"{recursive!r}; submodules are not fetched at "
                f"clone time."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path,
        description=(
            f"Pipeline {name!r} sets clone.recursive=true. Every "
            f"``.gitmodules``-declared URL is fetched on the "
            f"runner before any pipeline step runs."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
