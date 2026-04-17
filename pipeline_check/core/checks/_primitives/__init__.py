"""Cross-provider detection primitives.

Each module here exposes a pure text-level analysis routine that one
or more provider rule modules call. The goal is to own shared
detection logic in one place so per-provider rules collapse to a
thin wrapper that adapts the primitive's output into a
:class:`Finding`.

Primitives do **not** emit ``Finding`` objects themselves — they
return structured results (lists of offending snippets, booleans,
etc.) and leave presentation to the calling rule. This keeps the
primitive reusable across provider contexts whose resource
identifiers, severities, and prose differ.
"""
