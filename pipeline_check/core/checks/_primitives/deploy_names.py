"""Deploy-like job/workflow name regex.

Every provider's "deployment gating" rule needs to decide which jobs are
deployment jobs. The heuristic is a substring match on the job name, and
the vocabulary is provider-independent: ``deploy``, ``release``,
``publish``, ``promote``.

Owning the regex here means the vocabulary can grow (``rollout``,
``ship``) in one place instead of drifting across provider helpers.
"""
from __future__ import annotations

import re

DEPLOY_RE = re.compile(r"(?i)\b(deploy|release|publish|promote)\b")
