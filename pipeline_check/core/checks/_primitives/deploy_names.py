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

# Unattended IaC *apply* regex: a command that realizes infrastructure
# state from the repository's own IaC. Each one executes
# attacker-influenceable code at apply time (a Terraform ``external`` data
# source, a ``local-exec`` provisioner, a hijacked provider, a
# CloudFormation custom resource), so applying untrusted IaC is arbitrary
# code execution on the runner. Used by the "IaC apply on an untrusted
# trigger" rules across providers (GHA-117, GL-041). ``terraform plan`` /
# ``cdk diff`` are read-only and deliberately excluded (the apply / deploy
# verbs are the high-confidence shape); the ``destroy`` variants are
# included because they realize a state change just as apply does.
IAC_APPLY_RE = re.compile(
    r"\b(?:terraform|terragrunt|tofu)\s+(?:run-all\s+)?(?:apply|destroy)\b"
    r"|\baws\s+cloudformation\s+(?:deploy|create-stack|update-stack|execute-change-set)\b"
    r"|\bcdk\s+(?:deploy|destroy)\b"
    r"|\bpulumi\s+(?:up|destroy)\b"
    r"|\bsam\s+deploy\b",
    re.IGNORECASE,
)
