"""AWS-specific base check.

All AWS check modules subclass AWSBaseCheck, which wires the boto3 Session
into self.session so individual checks can create service clients with
self.session.client("service-name").
"""

import boto3

from pipeline_check.core.checks.base import BaseCheck, Finding, Severity


class AWSBaseCheck(BaseCheck):
    """Base class for all AWS check modules."""

    PROVIDER = "aws"

    def __init__(self, session: boto3.Session, target: str | None = None) -> None:
        super().__init__(context=session, target=target)
        self.session: boto3.Session = session
