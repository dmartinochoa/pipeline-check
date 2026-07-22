"""TKN-016. Remote resolver / bundle taskRef or pipelineRef not pinned."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import TektonContext, doc_location

RULE = Rule(
    id="TKN-016",
    title="Remote resolver taskRef / pipelineRef not pinned to an immutable revision",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every remote ``taskRef`` / ``pipelineRef`` to an immutable "
        "revision: a ``git`` resolver's ``revision`` to a full 40-hex "
        "commit SHA (not a branch or tag), a ``bundles`` resolver's "
        "``bundle`` image and the legacy ``taskRef.bundle`` to "
        "``@sha256:<digest>``, and a ``hub`` resolver to a specific "
        "``version`` (never ``latest``). Otherwise vendor the Task / "
        "Pipeline definition in-repo so it is reviewed and version-"
        "controlled like the rest of the pipeline."
    ),
    docs_note=(
        "Tekton's Resolution framework fetches the *body* of a Task or "
        "Pipeline at run time from a remote source. TKN-001 pins the "
        "container ``image`` a step runs, but a mutable resolver ref "
        "lets whoever controls the upstream (a Git branch, a floating "
        "OCI tag, a Hub ``latest``) swap the executed task body itself, "
        "running arbitrary steps under the run's ServiceAccount. The "
        "``cluster`` resolver is not flagged, it references an "
        "already-admitted in-cluster object rather than fetching remote "
        "content. Covers Pipeline ``spec.tasks`` / ``spec.finally`` "
        "``taskRef``, ``PipelineRun.spec.pipelineRef``, and "
        "``TaskRun.spec.taskRef``."
    ),
    exploit_example=(
        "# Vulnerable: the git resolver fetches the Task body from a\n"
        "# branch tip. Whoever can push to ``main`` on the upstream\n"
        "# repo changes what every PipelineRun executes.\n"
        "apiVersion: tekton.dev/v1\n"
        "kind: Pipeline\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  tasks:\n"
        "    - name: clone\n"
        "      taskRef:\n"
        "        resolver: git\n"
        "        params:\n"
        "          - { name: url, value: https://github.com/org/tasks }\n"
        "          - { name: revision, value: main }   # mutable\n"
        "          - { name: pathInRepo, value: git-clone.yaml }\n"
        "\n"
        "# Safe: pin the revision to a full commit SHA so the fetched\n"
        "# task body is content-addressed and cannot change underneath\n"
        "# the pipeline.\n"
        "          - { name: revision, value: 6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90 }"
    ),
)

# A git revision is pinned only when it is a full commit SHA (40 hex, or
# the 64-hex sha256 form). Branches, tags, and short SHAs are mutable.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _param(params: Any, name: str) -> str | None:
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("name") == name:
                v = p.get("value")
                return v if isinstance(v, str) else None
    return None


def _ref_unpinned(ref: Any) -> str | None:
    """Return a reason string if *ref* is an unpinned remote ref, else None."""
    if not isinstance(ref, dict):
        return None
    # Legacy ``taskRef.bundle`` (an OCI image reference).
    bundle = ref.get("bundle")
    if isinstance(bundle, str) and bundle.strip():
        if "@sha256:" not in bundle:
            return f"bundle '{bundle}' is not digest-pinned"
        return None

    resolver = ref.get("resolver")
    if not isinstance(resolver, str):
        return None
    params = ref.get("params")
    r = resolver.strip().lower()
    if r in ("bundles", "bundle"):
        img = _param(params, "bundle")
        if not img or "@sha256:" not in img:
            return "bundles resolver image is not digest-pinned"
    elif r == "git":
        rev = _param(params, "revision")
        if rev is None or not _SHA_RE.match(rev):
            return f"git resolver revision '{rev or '(default branch)'}' is not a commit SHA"
    elif r in ("hub", "hubresolver"):
        ver = _param(params, "version")
        if ver is None or ver.strip().lower() == "latest":
            return f"hub resolver version '{ver or '(latest)'}' is not pinned"
    # ``cluster`` and unknown resolvers reference admitted in-cluster
    # objects rather than fetching remote content, so they are not flagged.
    return None


def _pipeline_refs(doc_data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    spec = doc_data.get("spec")
    if not isinstance(spec, dict):
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for key in ("tasks", "finally"):
        v = spec.get(key)
        if isinstance(v, list):
            out.extend((key, t) for t in v if isinstance(t, dict))
    return out


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind == "Pipeline":
            examined += 1
            for _section, task in _pipeline_refs(doc.data):
                reason = _ref_unpinned(task.get("taskRef"))
                if reason:
                    name = task.get("name")
                    label = name if isinstance(name, str) and name else "?"
                    offenders.append(f"{doc.kind}/{doc.name} {label}: {reason}")
                    locations.append(doc_location(doc, task))
        elif doc.kind in ("PipelineRun", "TaskRun"):
            examined += 1
            spec = doc.data.get("spec")
            ref_key = "pipelineRef" if doc.kind == "PipelineRun" else "taskRef"
            ref = spec.get(ref_key) if isinstance(spec, dict) else None
            reason = _ref_unpinned(ref)
            if reason:
                offenders.append(f"{doc.kind}/{doc.name} {ref_key}: {reason}")
                locations.append(doc_location(doc))
            # A PipelineRun can embed the pipeline inline via
            # ``spec.pipelineSpec`` whose tasks carry their own
            # ``taskRef`` resolvers; walk those too.
            pspec = spec.get("pipelineSpec") if isinstance(spec, dict) else None
            if isinstance(pspec, dict):
                for _section, task in _pipeline_refs({"spec": pspec}):
                    task_reason = _ref_unpinned(task.get("taskRef"))
                    if task_reason:
                        name = task.get("name")
                        label = name if isinstance(name, str) and name else "?"
                        offenders.append(
                            f"{doc.kind}/{doc.name} pipelineSpec "
                            f"{label}: {task_reason}"
                        )
                        locations.append(doc_location(doc, task))

    if examined == 0:
        return RULE.pass_finding(
            "tekton",
            "No Pipeline / PipelineRun / TaskRun documents to check.",
        )
    passed = not offenders
    desc = (
        "Every remote taskRef / pipelineRef is pinned to an immutable "
        "revision."
        if passed else
        f"{len(offenders)} remote ref(s) are not pinned to an immutable "
        f"revision: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A mutable resolver ref "
        f"lets the upstream swap the executed task body."
    )
    return RULE.finding("tekton", desc, passed=passed, locations=locations)
