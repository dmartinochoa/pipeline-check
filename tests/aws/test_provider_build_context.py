"""AWS provider build_context error handling.

A bad ``--profile`` / ``AWS_PROFILE`` must surface as a clean ``ValueError``
(which the CLI maps to exit 2 with no traceback), not a raw botocore
``ProfileNotFound``.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.providers.aws import AWSProvider


def test_unknown_profile_raises_clean_valueerror():
    with pytest.raises(ValueError) as excinfo:
        AWSProvider().build_context(
            profile="pipeline_check_no_such_profile_xyz"
        )
    msg = str(excinfo.value)
    # Names the offending profile and points at the remediation.
    assert "could not be found" in msg
    assert "AWS_PROFILE" in msg
