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

    Each subclass receives a boto3 Session so it can create any service
    client it needs without the Scanner caring about which services are used.
    """

    def __init__(self, session: boto3.Session) -> None:
        self.session = session

    @abc.abstractmethod
    def run(self) -> list["Finding"]:
        """Execute all checks in this module and return findings."""
