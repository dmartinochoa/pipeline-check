"""Core data model for compliance standards."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ControlRef:
    """A reference to a single control within a named standard.

    This is what gets attached to a Finding. It carries enough metadata to
    render in reports (standard name, control id, human title) without the
    reporter having to load the full Standard.
    """

    standard: str        # e.g. "owasp_cicd_top_10"
    standard_title: str  # e.g. "OWASP Top 10 CI/CD Security Risks"
    control_id: str      # e.g. "CICD-SEC-5"
    control_title: str   # e.g. "Insufficient PBAC"

    def to_dict(self) -> dict:
        return {
            "standard": self.standard,
            "standard_title": self.standard_title,
            "control_id": self.control_id,
            "control_title": self.control_title,
        }

    def label(self) -> str:
        """Short human label — e.g. 'CICD-SEC-5: Insufficient PBAC'."""
        return f"{self.control_id}: {self.control_title}"


@dataclass
class Standard:
    """A compliance standard plus its mapping to this scanner's check IDs."""

    name: str                              # slug, e.g. "owasp_cicd_top_10"
    title: str                             # human title
    version: str = ""
    url: str = ""
    #: control_id -> control_title
    controls: dict[str, str] = field(default_factory=dict)
    #: check_id -> list of control_ids it maps to
    mappings: dict[str, list[str]] = field(default_factory=dict)

    def refs_for(self, check_id: str) -> list[ControlRef]:
        """Return ControlRefs for every control this standard maps to *check_id*."""
        refs: list[ControlRef] = []
        for ctrl_id in self.mappings.get(check_id, []):
            title = self.controls.get(ctrl_id, "")
            refs.append(ControlRef(
                standard=self.name,
                standard_title=self.title,
                control_id=ctrl_id,
                control_title=title,
            ))
        return refs
