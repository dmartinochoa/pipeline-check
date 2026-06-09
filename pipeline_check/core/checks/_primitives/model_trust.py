"""Shared detector for an ML model loaded with ``trust_remote_code``.

``trust_remote_code=True`` (or the ``--trust-remote-code`` CLI flag) tells
the transformers / huggingface_hub loader to execute the *model repo's own
Python* (``modeling_*.py``, custom pipelines) at load time. In a CI script
that is arbitrary code execution sourced from a model registry: a poisoned
or typosquatted model, or a compromised upstream, runs with the job's
secrets and token. The safe default is the library default
(``trust_remote_code=False``).

Provider-neutral, so every CI provider that runs inline ML scripts can
share one catalog: GHA-120 (GitHub), GL-045 (GitLab), BB-034 (Bitbucket).
"""
from __future__ import annotations

import re

TRUST_REMOTE_CODE_RE = re.compile(
    r"trust_remote_code\s*=\s*True|--trust[-_]remote[-_]code\b",
    re.IGNORECASE,
)
