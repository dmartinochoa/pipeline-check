"""MODEL-005. A vendored model config declares custom loader code.

A Hugging Face model's ``config.json`` can carry an ``auto_map`` block
that points the transformers auto-classes (``AutoModel``, ``AutoConfig``,
``AutoTokenizer``, …) at Python that lives in the *model repo itself*
(``modeling_*.py``, ``configuration_*.py``). When a pipeline loads that
model with ``trust_remote_code=True``, transformers imports and runs that
code, so a model carrying ``auto_map`` is arbitrary code that executes at
load time, sourced from whoever published the weights.

This is the *model side* of the ``trust_remote_code`` execution path that
the CI-script rules flag from the loader side (GHA-120 / GL-045): those
catch ``trust_remote_code=True`` in a build script; MODEL-005 catches the
vendored config that makes such a load run third-party code. A vendored
model with ``auto_map`` should be reviewed (read the referenced ``.py``)
and pinned, and loaded with ``trust_remote_code=False`` wherever possible.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ModelfileContext, config_custom_code

RULE = Rule(
    id="MODEL-005",
    title="Vendored model config declares custom loader code (auto_map)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-829", "CWE-94"),
    recommendation=(
        "Review the custom Python the ``auto_map`` references "
        "(``modeling_*.py`` / ``configuration_*.py`` in the model "
        "directory) the same way you would any dependency, and pin the "
        "model to an exact revision so the code can't change under you. "
        "Load the model with ``trust_remote_code=False`` (the library "
        "default) wherever the model works without its custom classes; if "
        "the custom code is required, load it in a job scoped to no "
        "production secrets. Prefer models that ship standard architectures "
        "and safetensors weights over ones that require remote code."
    ),
    docs_note=(
        "Fires on a vendored Hugging Face ``config.json`` whose "
        "``auto_map`` block is non-empty (the file is recognized as a "
        "model config by its ``auto_map`` / ``architectures`` / "
        "``model_type`` keys). ``auto_map`` points the transformers "
        "auto-classes at the model repo's own Python, which runs under "
        "``trust_remote_code=True``. The model-side complement of GHA-120 "
        "/ GL-045 (which flag the ``trust_remote_code`` load in CI "
        "scripts)."
    ),
)


def check(ctx: ModelfileContext) -> list[Finding]:
    findings: list[Finding] = []
    for mc in ctx.model_configs:
        refs = config_custom_code(mc.data)
        passed = not refs
        desc = (
            "The model config declares no custom loader code (no auto_map)."
            if passed else
            f"The model config declares {len(refs)} custom-code reference(s) "
            f"in auto_map ({', '.join(refs[:5])}"
            f"{'…' if len(refs) > 5 else ''}); loading this model with "
            "trust_remote_code=True runs the model repo's own Python at "
            "load time."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=mc.path, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            locations=[Location(path=mc.path, start_line=1, end_line=1)]
            if not passed else [],
        ))
    return findings
