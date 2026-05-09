"""Drone CI provider, parses ``.drone.yml`` / ``.drone.yaml``.

Drone pipelines are multi-document YAML, each document is a
top-level pipeline with a ``kind: pipeline`` discriminator and a
``type:`` (``docker``, ``kubernetes``, ``ssh``, ``exec``,
``digitalocean``). The scanner targets the most-used ``docker``
type; ``kubernetes`` pipelines borrow the same step shape and
the rules apply unchanged. Other types
(``ssh`` / ``exec`` / ``digitalocean``) are loaded but most rules
no-op on them.

Each step has an ``image:`` (run inside a container), an optional
``commands:`` list (shell commands), an optional ``settings:``
block (plugin config), an ``environment:`` block, and ``when:``
filters. Drone substitutes ``${DRONE_*}`` template variables
*before* the shell parses the script, so any unquoted use is a
command-injection primitive (mirrors the same pattern as the
Tekton / Argo / Buildkite parameter-injection rules).

The provider is opt-in (``--pipeline drone``) and auto-detects
``.drone.yml`` / ``.drone.yaml`` at cwd.
"""
