import abc
from dataclasses import dataclass
from enum import Enum

import boto3


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
    owasp_cicd: str
    passed: bool

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource": self.resource,
            "description": self.description,
            "recommendation": self.recommendation,
            "owasp_cicd": self.owasp_cicd,
            "passed": self.passed,
        }


class BaseCheck(abc.ABC):
    """Abstract base for all check modules.

    Each subclass declares a PROVIDER class attribute so the Scanner can
    route it to the correct pipeline environment.  AWS checks receive a
    boto3 Session; future providers should override __init__ to accept
    whatever client/credentials object they need.
    """

    #: Pipeline environment this check targets.  Override in subclasses.
    PROVIDER: str = "aws"

    def __init__(self, session: boto3.Session) -> None:
        self.session = session

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""
