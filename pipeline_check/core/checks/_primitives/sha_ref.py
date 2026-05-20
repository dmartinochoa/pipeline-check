"""Shared SHA-1 commit-ref regex used by every "is this a pinned SHA?" check.

Provider rules that walk action references (GHA-001 ``uses:``,
ADO-025 ``ref:``, NPM-005 / PYPI-004 git-VCS spec refs) all need
the same "40-char hex" predicate. Six near-identical
``re.compile(r"^[0-9a-f]{40}$")`` lines lived across the rule pack
until this module was introduced. Two flavors are exported because
the npm / pypi sides accept uppercase hex in ``#`` git refs while
git's own canonical form is lowercase.
"""
from __future__ import annotations

import re

#: Lowercase 40-char hex SHA-1. Matches git's canonical form.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: Case-insensitive variant for ecosystems (npm / pypi dependency
#: specs) where uppercase hex is occasionally seen in the ``#<ref>``
#: position.
SHA_RE_IGNORECASE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
