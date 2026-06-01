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

# Deploy-like *command* regex: a shell command that pushes state to a
# real deployment target. Used by the "ungated deploy" rules that
# recognize a deploy job by what it runs, not just its name (GHA-014,
# GHA-112). Owned here so the vocabulary grows in one place.
DEPLOY_CMD_RE = re.compile(
    r"(?:kubectl\s+(?:apply|create|set\s+image|rollout\s+restart)"
    r"|terraform\s+(?:apply|destroy)"
    r"|aws\s+(?:s3\s+(?:cp|sync)|cloudformation\s+deploy|ecs\s+update-service)"
    r"|docker\s+push"
    r"|helm\s+(?:upgrade|install)"
    r"|gcloud\s+(?:app\s+deploy|run\s+deploy|functions\s+deploy)"
    r"|ansible-playbook"
    r"|serverless\s+deploy"
    r"|az\s+(?:webapp\s+deploy|functionapp\s+deploy|containerapp\s+update))",
    re.IGNORECASE,
)
