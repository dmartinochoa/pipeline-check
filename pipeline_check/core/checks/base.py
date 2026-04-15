import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..standards.base import ControlRef


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Ascending order: INFO is least severe, CRITICAL is most severe.
_SEVERITY_RANK: dict["Severity", int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(s: "Severity") -> int:
    return _SEVERITY_RANK[s]


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    description: str
    recommendation: str
    passed: bool
    #: Compliance controls this finding evidences. Populated by the Scanner
    #: from the standards registry after a check runs; checks never set this
    #: directly.
    controls: list[ControlRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "recommendation": self.recommendation,
            "passed": self.passed,
            "controls": [c.to_dict() for c in self.controls],
        }


class BaseCheck(abc.ABC):
    """Provider-agnostic base for all check modules.

    Subclasses declare a PROVIDER class attribute so the Scanner can route
    them to the correct pipeline environment, and accept whatever context
    object their provider requires (e.g. a boto3 Session for AWS, a
    google-auth credential for GCP, a token for GitHub).
    """

    #: Pipeline environment this check targets.  Override in subclasses.
    PROVIDER: str = ""

    def __init__(self, context: Any, target: str | None = None) -> None:
        self.context = context
        #: Optional resource name to scope the scan to (e.g. a pipeline name).
        self.target = target

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""
