"""Build-time dependency model and PURL generation for SBOM output.

A :class:`BuildDependency` captures one build-time dependency the
scanner extracted from a pipeline config (an action reference, a
Docker base image, an npm package, etc.). The CycloneDX reporter
formats a list of these into a spec-compliant BOM.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True, slots=True)
class BuildDependency:
    """One build-time dependency extracted from a pipeline config."""

    name: str
    version: str
    dep_type: str
    purl: str
    provider: str
    source: str
    pinned: bool
    digest: str = ""

    def bom_ref(self) -> str:
        slug = re.sub(r"[^a-zA-Z0-9._-]", "-", f"{self.name}-{self.version}")
        return slug[:120]


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][-A-Za-z0-9_.]*(?:\[[^\]]+\])?)\s*"
    r"(?:[!=<>~]+\s*([^\s,;#]+))?",
)


def make_github_purl(
    owner: str,
    repo: str,
    ref: str,
    path: str = "",
) -> str:
    base = f"pkg:github/{_purl_encode(owner)}/{_purl_encode(repo)}@{_purl_encode(ref)}"
    if path:
        base += f"?subpath={_purl_encode(path)}"
    return base


def make_docker_purl(image: str, tag: str, digest: str = "") -> str:
    parts = image.split("/")
    if len(parts) == 1:
        name = parts[0]
        namespace = ""
    elif len(parts) == 2 and "." not in parts[0]:
        namespace = parts[0]
        name = parts[1]
    else:
        namespace = "/".join(parts[:-1])
        name = parts[-1]

    base = "pkg:docker/"
    if namespace:
        base += f"{_purl_encode(namespace)}/"
    base += _purl_encode(name)

    if digest:
        base += f"@{_purl_encode(digest)}"
    elif tag:
        base += f"@{_purl_encode(tag)}"
    return base


def make_npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{_purl_encode(scope)}/{_purl_encode(pkg)}@{_purl_encode(version)}"
    return f"pkg:npm/{_purl_encode(name)}@{_purl_encode(version)}"


def make_pypi_purl(name: str, version: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{_purl_encode(normalized)}@{_purl_encode(version)}"


def make_maven_purl(group: str, artifact: str, version: str) -> str:
    return (
        f"pkg:maven/{_purl_encode(group)}/{_purl_encode(artifact)}"
        f"@{_purl_encode(version)}"
    )


def make_nuget_purl(name: str, version: str) -> str:
    return f"pkg:nuget/{_purl_encode(name)}@{_purl_encode(version)}"


def _purl_encode(segment: str) -> str:
    return quote(segment, safe="")


def parse_docker_ref(ref: str) -> tuple[str, str, str]:
    """Split a Docker image reference into (image, tag, digest).

    Handles: ``python:3.12``, ``ghcr.io/owner/img:v1``,
    ``python@sha256:abc...``, ``python:3.12@sha256:abc...``.
    """
    digest = ""
    if "@" in ref:
        ref, _, digest = ref.rpartition("@")

    tag = ""
    last_colon = ref.rfind(":")
    if last_colon > 0:
        candidate_tag = ref[last_colon + 1:]
        if "/" not in candidate_tag:
            tag = candidate_tag
            ref = ref[:last_colon]

    return ref, tag, digest


def parse_requirement_line(body: str) -> tuple[str, str] | None:
    """Extract (name, version) from a pip requirements line.

    Returns ``None`` for options lines (``-r``, ``--index-url``, etc.),
    comments, and unpinned requirements.
    """
    stripped = body.strip()
    if not stripped or stripped.startswith(("#", "-")):
        return None
    m = _REQUIREMENT_RE.match(stripped)
    if m and m.group(2):
        return m.group(1).split("[")[0], m.group(2)
    return None


def deduplicate(deps: list[BuildDependency]) -> list[BuildDependency]:
    """Remove duplicate dependencies by purl, keeping the first."""
    seen: set[str] = set()
    out: list[BuildDependency] = []
    for d in deps:
        if d.purl not in seen:
            seen.add(d.purl)
            out.append(d)
    return out


__all__ = [
    "BuildDependency",
    "deduplicate",
    "make_docker_purl",
    "make_github_purl",
    "make_maven_purl",
    "make_npm_purl",
    "make_nuget_purl",
    "make_pypi_purl",
    "parse_docker_ref",
    "parse_requirement_line",
]
