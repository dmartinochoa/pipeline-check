"""Component inventory — what the scanner actually saw.

Findings answer "what's wrong". The inventory answers "what was
scanned". Together they let downstream tooling (SOC2/PCI audit
dashboards, drift detectors, change trackers) correlate "this
resource was present on this date and produced these findings".

Every provider implements ``BaseProvider.inventory(context) ->
list[Component]``; default is an empty list so providers that don't
care pay nothing. Components are deliberately flat — the ``metadata``
dict carries provider-specific details without forcing a taxonomy on
the top-level schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Component:
    """A single resource/file/workflow the scanner discovered."""

    #: Provider that produced this component (``"aws"``, ``"terraform"``,
    #: ``"cloudformation"``, ``"github"``, etc.). Matches
    #: ``BaseProvider.NAME``.
    provider: str

    #: Component type. Shape varies by provider:
    #:   - AWS runtime: ``"codebuild_project"``, ``"iam_role"``, ...
    #:   - Terraform: ``"aws_codebuild_project"`` (the HCL resource type)
    #:   - CloudFormation: ``"AWS::CodeBuild::Project"``
    #:   - Workflow providers: ``"workflow"``, ``"pipeline"``, or ``"jenkinsfile"``
    type: str

    #: Human-meaningful identifier — bucket name, role name, workflow
    #: filename, Terraform address, CFN logical id. Must be unique
    #: within ``(provider, type)`` for a given scan so consumers can
    #: correlate with findings.
    identifier: str

    #: Where the component came from — a file path for shift-left
    #: providers, an ARN or region for live AWS, an empty string when
    #: no better provenance is available.
    source: str = ""

    #: Provider-specific attributes kept out of the top-level schema so
    #: new fields don't become breaking changes. Keep keys flat
    #: (``tags``, ``encrypted``, ``stages``) rather than deeply nested.
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "type": self.type,
            "identifier": self.identifier,
            "source": self.source,
            "metadata": self.metadata,
        }
