"""Maven context and base check.

Loads ``pom.xml`` / ``settings.xml`` / ``build.gradle`` /
``build.gradle.kts`` documents from disk and exposes parsed
:class:`PomFile` objects to per-rule modules. Rule modules subclass-
free: each rule's ``check()`` takes a ``PomFile`` and returns a
``Finding``; the orchestrator runs every rule against every loaded
file.

Gradle files are read by a regex-based extractor
(:func:`_parse_gradle`) that emits the same ``PomFile`` shape from
``"group:artifact:version"`` coordinate strings, ``group:`` /
``name:`` / ``version:`` map-form deps, and ``maven { url ... }``
repository blocks. Existing ``MVN-NNN`` rules apply to Gradle
projects without per-rule changes. Variable substitution
(``${junitVersion}``) is left unresolved for the first cut — this
matches the limitation Gradle-scanning tools commonly accept and
keeps the parser deterministic without a full DSL evaluation.

Parser scope (POM)
------------------
The XML parser handles the four shapes the rule pack reasons about:

* ``<dependencies><dependency>...</dependency></dependencies>``,
  including ``<dependencyManagement>``.
* ``<repositories><repository>...``, ``<pluginRepositories>``,
  ``<distributionManagement>``.
* ``<settings><mirrors><mirror>...`` (when a settings.xml is passed).
* ``<properties>`` for ``${...}`` variable substitution in version
  literals.

XML parsing is intentionally tolerant. A malformed file is captured
as a warning on the context rather than raised; the goal is best-
effort static analysis over a repo tree.
"""
from __future__ import annotations

import datetime as _dt
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

#: Filenames the loader picks up. ``pom.xml`` is the canonical Maven
#: project descriptor; ``settings.xml`` is the per-user / per-CI Maven
#: config that carries ``<mirrors>`` and ``<servers>`` entries.
MANIFEST_NAMES: frozenset[str] = frozenset({"pom.xml"})
SETTINGS_NAMES: frozenset[str] = frozenset({"settings.xml"})
#: Gradle build script filenames. Both the Groovy DSL
#: (``build.gradle``) and Kotlin DSL (``build.gradle.kts``) are
#: recognized; the same regex-based extractor handles both because
#: the coordinate-string and ``maven {}`` shapes are syntactically
#: identical between the two dialects.
GRADLE_NAMES: frozenset[str] = frozenset({
    "build.gradle", "build.gradle.kts",
})

#: Default Maven 4 POM namespace. Stripped during parsing so rule code
#: can match unprefixed tag names.
_POM_NS = re.compile(r"^\{[^}]+\}")


@dataclass(frozen=True, slots=True)
class MavenDependency:
    """One declared dependency on a Maven artifact."""

    group_id: str
    artifact_id: str
    #: ``None`` when the dependency omits ``<version>`` (relies on
    #: ``<dependencyManagement>`` or a parent POM to resolve it).
    version: str | None
    scope: str = "compile"
    #: ``True`` when this dependency was declared inside
    #: ``<dependencyManagement>`` (version-management section, not a
    #: real dep). Rules that target *real* dependencies should skip
    #: managed entries; rules that audit version-management posture
    #: include them.
    managed: bool = False
    line_no: int = 1

    @property
    def coordinate(self) -> str:
        v = self.version or "<unmanaged>"
        return f"{self.group_id}:{self.artifact_id}:{v}"


@dataclass(frozen=True, slots=True)
class MavenRepository:
    """One ``<repository>`` / ``<pluginRepository>`` entry."""

    id: str
    url: str
    releases_enabled: bool = True
    snapshots_enabled: bool = False
    #: ``"warn"`` / ``"fail"`` / ``"ignore"`` / ``None`` (= default).
    #: Maven's default is ``"warn"`` (log the mismatch and continue);
    #: only ``"fail"`` is a hard checksum gate.
    checksum_policy: str | None = None
    #: Source section, so rules can distinguish runtime repos from
    #: plugin repos.
    section: str = "repositories"
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class MavenMirror:
    """One ``<mirror>`` entry from ``settings.xml``."""

    id: str
    url: str
    #: Maven's mirror-of pattern: ``central``, ``*``, ``external:*``,
    #: ``!internal,*``, etc. ``*`` and ``external:*`` are the patterns
    #: that route arbitrary external traffic through this mirror and
    #: are the supply-chain concern.
    mirror_of: str = ""
    line_no: int = 1


@dataclass(frozen=True, slots=True)
class PomFile:
    """A parsed ``pom.xml`` (or ``settings.xml`` masquerading as one)."""

    path: str
    text: str
    #: ``True`` for a ``settings.xml`` payload (mirrors / servers /
    #: profiles); ``False`` for a project POM.
    is_settings: bool = False
    dependencies: tuple[MavenDependency, ...] = field(default_factory=tuple)
    repositories: tuple[MavenRepository, ...] = field(default_factory=tuple)
    mirrors: tuple[MavenMirror, ...] = field(default_factory=tuple)
    #: ``<properties>`` map for ``${...}`` substitution.
    properties: dict[str, str] = field(default_factory=dict)
    #: ``True`` when the XML parsed cleanly. ``False`` on malformed
    #: input; rules should short-circuit pass in that case so a
    #: parse error doesn't cascade into N false-positive findings.
    parsed_ok: bool = True


class MavenContext:
    """Loaded set of ``pom.xml`` / ``settings.xml`` documents."""

    def __init__(self, files: list[PomFile]) -> None:
        self.files = files
        self.files_scanned: int = len(files)
        self.files_skipped: int = 0
        self.warnings: list[str] = []
        #: ``{"group:artifact": {version: utc_timestamp}}`` populated
        #: by the maven provider's ``post_filter`` when
        #: ``--resolve-remote`` is on. Empty by default; MVN-008
        #: (cooldown gate) reads it and passes silently when the
        #: dict is empty so the rule's absence isn't a CI failure
        #: for users on the default no-network path.
        self.publish_times: dict[str, dict[str, _dt.datetime]] = {}

    @classmethod
    def from_path(cls, path: str | Path) -> MavenContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--maven-path {root} does not exist. Pass a pom.xml "
                "file or a directory containing one."
            )
        if root.is_file():
            candidates = [root]
        else:
            names = MANIFEST_NAMES | SETTINGS_NAMES | GRADLE_NAMES
            candidates = sorted(
                p for p in root.rglob("*")
                if p.is_file()
                and p.name in names
                # Skip vendored copies / build outputs.
                and "target" not in p.parts
                and ".m2" not in p.parts
                and "build" not in p.parts
                and ".gradle" not in p.parts
            )
        files: list[PomFile] = []
        warnings: list[str] = []
        skipped = 0
        for f in candidates:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            if f.name in GRADLE_NAMES:
                scan_dir = root if root.is_dir() else root.parent
                cross_file = _discover_gradle_cross_file_properties(
                    f, scan_dir,
                )
                catalog = _discover_gradle_version_catalog(f, scan_dir)
                pf = _parse_gradle(
                    str(f),
                    text,
                    extra_properties=cross_file,
                    version_catalog=catalog,
                )
            else:
                pf = _parse_pom(str(f), text)
                if not pf.parsed_ok:
                    warnings.append(f"{f}: XML parse error")
                    skipped += 1
                    continue
            files.append(pf)
        ctx = cls(files)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


class MavenBaseCheck(BaseCheck[MavenContext]):
    """Base class for maven rule modules."""

    PROVIDER = "maven"

    def __init__(self, ctx: MavenContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: MavenContext = ctx


# ── Parser ─────────────────────────────────────────────────────────────


def _strip_ns(tag: str) -> str:
    return _POM_NS.sub("", tag)


def _findtext(elem: ET.Element, name: str, default: str = "") -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return default


def _find_child(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _findall_children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if _strip_ns(c.tag) == name]


def _bool_text(text: str, default: bool) -> bool:
    if not text:
        return default
    return text.strip().lower() == "true"


def _line_of(text: str, needle: str, start: int = 0) -> int:
    """1-based line of the first ``needle`` after byte offset ``start``."""
    idx = text.find(needle, start)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def _parse_pom(path: str, text: str) -> PomFile:
    """Parse a ``pom.xml`` / ``settings.xml`` body into a :class:`PomFile`.

    On a parse error returns a ``PomFile(parsed_ok=False)`` so the
    caller can skip with a warning. The text is preserved on the
    returned object so rules can run line-number lookups against the
    original source.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return PomFile(path=path, text=text, parsed_ok=False)

    root_tag = _strip_ns(root.tag)
    is_settings = root_tag == "settings"

    properties: dict[str, str] = {}
    props = _find_child(root, "properties")
    if props is not None:
        for child in props:
            key = _strip_ns(child.tag)
            value = (child.text or "").strip()
            if key:
                properties[key] = value

    dependencies: list[MavenDependency] = []
    repositories: list[MavenRepository] = []
    mirrors: list[MavenMirror] = []

    if not is_settings:
        # Top-level <dependencies>
        deps_node = _find_child(root, "dependencies")
        if deps_node is not None:
            for dep in _findall_children(deps_node, "dependency"):
                dependencies.append(_parse_dependency(dep, text, managed=False))
        # <dependencyManagement><dependencies>
        dm_node = _find_child(root, "dependencyManagement")
        if dm_node is not None:
            inner = _find_child(dm_node, "dependencies")
            if inner is not None:
                for dep in _findall_children(inner, "dependency"):
                    dependencies.append(_parse_dependency(dep, text, managed=True))
        # <repositories> and <pluginRepositories>
        for section in ("repositories", "pluginRepositories"):
            node = _find_child(root, section)
            if node is None:
                continue
            child_name = section[:-3] + "y"  # repositories -> repository
            for repo in _findall_children(node, child_name):
                repositories.append(_parse_repository(repo, text, section=section))
        # <distributionManagement> may carry <repository> + <snapshotRepository>
        dist = _find_child(root, "distributionManagement")
        if dist is not None:
            for tag in ("repository", "snapshotRepository"):
                node = _find_child(dist, tag)
                if node is not None:
                    repositories.append(
                        _parse_repository(node, text, section="distributionManagement"),
                    )

    # settings.xml: <mirrors><mirror>
    if is_settings:
        mirrors_node = _find_child(root, "mirrors")
        if mirrors_node is not None:
            for m in _findall_children(mirrors_node, "mirror"):
                mirrors.append(_parse_mirror(m, text))

    return PomFile(
        path=path,
        text=text,
        is_settings=is_settings,
        dependencies=tuple(dependencies),
        repositories=tuple(repositories),
        mirrors=tuple(mirrors),
        properties=properties,
        parsed_ok=True,
    )


def _parse_dependency(
    elem: ET.Element, text: str, *, managed: bool,
) -> MavenDependency:
    group_id = _findtext(elem, "groupId")
    artifact_id = _findtext(elem, "artifactId")
    version_raw = _findtext(elem, "version")
    version: str | None = version_raw if version_raw else None
    scope = _findtext(elem, "scope") or "compile"
    line_no = _line_of(text, f"<artifactId>{artifact_id}</artifactId>")
    return MavenDependency(
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        scope=scope,
        managed=managed,
        line_no=line_no,
    )


def _parse_repository(
    elem: ET.Element, text: str, *, section: str,
) -> MavenRepository:
    repo_id = _findtext(elem, "id")
    url = _findtext(elem, "url")
    releases = _find_child(elem, "releases")
    snapshots = _find_child(elem, "snapshots")
    releases_enabled = (
        _bool_text(_findtext(releases, "enabled"), default=True)
        if releases is not None else True
    )
    snapshots_enabled = (
        _bool_text(_findtext(snapshots, "enabled"), default=False)
        if snapshots is not None else False
    )
    # Checksum policy may be declared on either <releases> or
    # <snapshots>; rules care about the most permissive value.
    policies: list[str] = []
    for node in (releases, snapshots):
        if node is None:
            continue
        cp = _findtext(node, "checksumPolicy")
        if cp:
            policies.append(cp.strip().lower())
    checksum_policy: str | None
    if "ignore" in policies:
        checksum_policy = "ignore"
    elif "warn" in policies:
        checksum_policy = "warn"
    elif "fail" in policies:
        checksum_policy = "fail"
    else:
        checksum_policy = None
    line_no = _line_of(text, f"<id>{repo_id}</id>") if repo_id else 1
    return MavenRepository(
        id=repo_id,
        url=url,
        releases_enabled=releases_enabled,
        snapshots_enabled=snapshots_enabled,
        checksum_policy=checksum_policy,
        section=section,
        line_no=line_no,
    )


def _parse_mirror(elem: ET.Element, text: str) -> MavenMirror:
    mirror_id = _findtext(elem, "id")
    url = _findtext(elem, "url")
    mirror_of = _findtext(elem, "mirrorOf")
    line_no = _line_of(text, f"<id>{mirror_id}</id>") if mirror_id else 1
    return MavenMirror(
        id=mirror_id, url=url, mirror_of=mirror_of, line_no=line_no,
    )


# ── Gradle parser ──────────────────────────────────────────────────────


# A Maven coordinate inside a quoted string:
#   "org.apache.commons:commons-text:1.10.0"
#   'org.apache.logging.log4j:log4j-core:2.14.1'
# Captures group:artifact:version. Trailing ``:classifier`` /
# ``@type`` (sources, javadoc, war) is consumed but discarded so the
# version stays clean. The version body accepts letters, digits,
# dots, hyphens, underscores, plus ``+`` and ``[``/``]``/``(``/``)``
# / ``,`` so MVN-001 still sees the floating-range shape and flags
# it; ``${prop}`` is similarly preserved.
_GRADLE_COORD_RE = re.compile(
    r"""(?P<q>['"])
        (?P<group>[\w.+-]+)
        :
        (?P<artifact>[\w.+-]+)
        :
        (?P<version>[\w.+\-${}\[\](),]+)
        (?:[:@][\w-]+)?
        (?P=q)
    """,
    re.VERBOSE,
)

# Map-form dep declaration:
#   group: 'X', name: 'Y', version: 'Z'
#   group = "X", name = "Y", version = "Z"   (Kotlin DSL)
# All three fields are required; Gradle named arguments are
# order-insensitive in both Groovy and Kotlin DSL, so a window
# regex finds three "key: 'value'" pairs in any order and three
# per-key extractors then pull the actual coordinate. Capture
# fields ``group``, ``artifact``, ``version`` on each per-key
# match's ``value`` named group.
_GRADLE_MAP_KEY_VALUE = (
    r"""\b(?:group|name|version)\s*[:=]\s*['"][^'"\n]{1,256}['"]"""
)
_GRADLE_MAP_DEP_WINDOW_RE = re.compile(
    rf"""{_GRADLE_MAP_KEY_VALUE}
        \s*,?\s*
        {_GRADLE_MAP_KEY_VALUE}
        \s*,?\s*
        {_GRADLE_MAP_KEY_VALUE}
    """,
    re.VERBOSE,
)
_GRADLE_MAP_GROUP_RE = re.compile(
    r"""\bgroup\s*[:=]\s*(['"])(?P<value>[\w.+-]+)\1""",
)
_GRADLE_MAP_NAME_RE = re.compile(
    r"""\bname\s*[:=]\s*(['"])(?P<value>[\w.+-]+)\1""",
)
_GRADLE_MAP_VERSION_RE = re.compile(
    r"""\bversion\s*[:=]\s*(['"])(?P<value>[\w.+\-${}\[\](),]+)\1""",
)

# Maven repository URL inside a ``maven { ... }`` block. Three real-
# world shapes:
#   maven { url 'http://example.com/repo' }              (Groovy)
#   maven { url = 'http://example.com/repo' }
#   maven { url = uri("http://example.com/repo") }       (Kotlin DSL)
#   maven { setUrl("http://example.com/repo") }
# We match ``url[\s=]+(uri\()?(['"])URL\2\)?`` inside a ``maven``
# block; the trailing optional ``)`` from the ``uri(...)`` wrapper
# is allowed but not required.
_GRADLE_MAVEN_URL_RE = re.compile(
    r"""maven\s*[({]
        [^}]*?
        (?:url\s*=?\s*|setUrl\s*\(\s*)
        (?:uri\s*\(\s*)?
        (?P<q>['"])
        (?P<url>[^\s'"]+)
        (?P=q)
    """,
    re.VERBOSE | re.DOTALL,
)

# Single-arg ``maven("URL")`` shorthand. Some Gradle Kotlin scripts
# pass the URL directly as the function argument instead of inside a
# block.
_GRADLE_MAVEN_SHORT_RE = re.compile(
    r"""maven\s*\(\s*
        (?P<q>['"])
        (?P<url>[^\s'"]+)
        (?P=q)
        \s*\)
    """,
    re.VERBOSE,
)


# ── Gradle property extraction ─────────────────────────────────────────
#
# Gradle exposes user-declared properties in three in-file shapes that
# this parser resolves so MVN-001 (floating-range / LATEST) and
# MVN-008 (cooldown) see the literal version the build actually pins
# rather than the ``${prop}`` reference.
#
#   ext { logVer = '2.14.1' }                  (Groovy ext block)
#   ext.logVer = '2.14.1'                      (Groovy ext property)
#   def logVer = '2.14.1'                      (Groovy local def)
#   val logVer = "2.14.1"                      (Kotlin DSL local val)
#   val logVer: String = "2.14.1"              (Kotlin DSL with type ann)
#
# Cross-file ``gradle.properties`` and ``libs.versions.toml`` version
# catalogs are deliberately out of scope for this pass.

# Match ``key = "value"`` or ``key = 'value'`` (with optional ``=``).
# Inside the ``ext { ... }`` block Groovy accepts both ``logVer = '2'``
# and the bare ``logVer '2'`` (script-config DSL) shape; the regex
# covers the leading-``=`` form which is by far the common one.
_GRADLE_EXT_OPEN_RE = re.compile(r"\bext\s*\{")
_GRADLE_PROP_ASSIGN_RE = re.compile(
    r"""(?P<name>[A-Za-z_][\w.]*)
        \s*=\s*
        (?P<q>['"])(?P<value>[^'"\n]{0,256})(?P=q)
    """,
    re.VERBOSE,
)
_GRADLE_EXT_DOT_RE = re.compile(
    r"""\bext\.(?P<name>[A-Za-z_][\w.]*)
        \s*=\s*
        (?P<q>['"])(?P<value>[^'"\n]{0,256})(?P=q)
    """,
    re.VERBOSE,
)
_GRADLE_DEF_RE = re.compile(
    r"""(?:^|\n)\s*def\s+(?P<name>[A-Za-z_][\w]*)
        \s*=\s*
        (?P<q>['"])(?P<value>[^'"\n]{0,256})(?P=q)
    """,
    re.VERBOSE,
)
_GRADLE_VAL_RE = re.compile(
    r"""(?:^|\n)\s*val\s+(?P<name>[A-Za-z_][\w]*)
        (?:\s*:\s*\w[\w<>,?\s]*)?
        \s*=\s*
        (?P<q>['"])(?P<value>[^'"\n]{0,256})(?P=q)
    """,
    re.VERBOSE,
)
# ``$prop`` / ``${prop}`` references inside a coordinate's version
# field. Used to substitute property values back into the version
# string before the MVN-* rules see it.
_GRADLE_VERSION_REF_RE = re.compile(
    r"""\$\{?(?P<name>[A-Za-z_][\w.]*)\}?""",
)

# Catalog accessor references in build scripts:
#
#     implementation libs.junit.jupiter
#     implementation(libs.spring.boot.starter)
#     testImplementation libs.junit.engine
#
# Matches ``libs.<dot.path>`` anchored on a word boundary so it
# doesn't grab partial identifiers. The first segment after ``libs.``
# is captured so the dispatcher can skip the version-only (``libs.
# versions.X``) and bundle (``libs.bundles.X``) namespaces.
_GRADLE_CATALOG_REF_RE = re.compile(
    r"""\blibs\.(?P<head>[a-zA-Z][\w]*)(?P<rest>(?:\.[a-zA-Z][\w]*)*)""",
)
# Configurations Gradle recognizes for the ``dependencies { }`` DSL.
# Restricting catalog-ref detection to these configuration verbs
# avoids matching ``libs.X.Y`` inside unrelated text (e.g. a comment
# referencing ``libs.foo``).
_GRADLE_CATALOG_DEP_CONFIGS: tuple[str, ...] = (
    "api", "implementation", "compileOnly", "runtimeOnly",
    "testImplementation", "testCompileOnly", "testRuntimeOnly",
    "annotationProcessor", "kapt", "ksp",
    "androidTestImplementation", "debugImplementation",
    "releaseImplementation",
)
_GRADLE_CATALOG_LINE_RE = re.compile(
    r"""\b(?P<config>"""
    + "|".join(_GRADLE_CATALOG_DEP_CONFIGS)
    + r""")\s*\(?\s*libs\.""",
)


def _ext_block_bodies(text: str) -> list[str]:
    """Yield the body of each ``ext { ... }`` block, brace-aware.

    A regex with ``[^{}]*`` for the body fails the moment the block
    contains a nested brace (closures, conditional sub-blocks, map /
    list literals with ``{}``). Walk the source counting braces so
    bodies with arbitrary nesting are extracted intact. Naive about
    strings (a ``"}"`` literal inside a value would terminate the
    block early), but Gradle scripts almost never embed braces in
    quoted property values, so the false-positive rate is negligible
    vs. the false-negative caused by the regex shape.
    """
    out: list[str] = []
    for opener in _GRADLE_EXT_OPEN_RE.finditer(text):
        depth = 1
        i = opener.end()
        body_start = i
        n = len(text)
        while i < n and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        if depth == 0:
            out.append(text[body_start:i - 1])
    return out


def _extract_gradle_properties(text: str) -> dict[str, str]:
    """Return ``{name: value}`` for every in-file user-declared property.

    Walks each Gradle property shape (``ext { ... }`` blocks, bare
    ``ext.foo = ...`` lines, Groovy ``def`` declarations, Kotlin DSL
    ``val`` declarations) and returns the merged map. When the same
    name is assigned more than once the later assignment wins,
    matching Gradle's last-write semantics for in-script properties.
    """
    out: dict[str, str] = {}
    # ``ext { ... }`` blocks first so a later same-named ``ext.foo``
    # outside the block still wins.
    for body in _ext_block_bodies(text):
        for am in _GRADLE_PROP_ASSIGN_RE.finditer(body):
            out[am.group("name")] = am.group("value")
    for m in _GRADLE_EXT_DOT_RE.finditer(text):
        out[m.group("name")] = m.group("value")
    for m in _GRADLE_DEF_RE.finditer(text):
        out[m.group("name")] = m.group("value")
    for m in _GRADLE_VAL_RE.finditer(text):
        out[m.group("name")] = m.group("value")
    return out


def _parse_gradle_properties(text: str) -> dict[str, str]:
    """Parse a Java-properties body (``gradle.properties``).

    Supports the ``key=value`` and ``key = value`` forms. Skips
    blank lines, ``#`` / ``!`` comments, and line-continuation
    backslashes (those are rare in real ``gradle.properties`` and
    folding them precisely matches the Java spec, which would
    require buffering. The simpler line-at-a-time parser handles
    the overwhelming majority of real-world files).
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line and ":" not in line:
            continue
        # Java-properties accepts both ``=`` and ``:`` as separators
        # (with optional whitespace). Pick whichever appears first.
        eq = line.find("=")
        colon = line.find(":")
        if eq < 0:
            idx = colon
        elif colon < 0:
            idx = eq
        else:
            idx = min(eq, colon)
        key = line[:idx].strip()
        value = line[idx + 1:].strip()
        if key:
            out[key] = value
    return out


VersionCatalog = dict[str, tuple[str, str, str]]
"""Mapping from a normalized DSL name (``junit.jupiter``) to
``(group_id, artifact_id, resolved_version)``. The DSL name uses
``.`` as a separator the way Gradle's generated accessor does
(catalog entries written with ``-`` are normalized to ``.``).
Empty when no catalog was discovered, the parser silent-passes
that case so a project without a catalog isn't penalized.
"""


def _parse_versions_catalog(text: str) -> VersionCatalog:
    """Parse a ``libs.versions.toml`` body.

    Returns a ``{dotted_name: (group, artifact, version)}`` index.
    Handles both library entry shapes Gradle accepts:

    * ``module = "group:artifact"`` (newer single-string form)
    * ``group = "..." , name = "..."`` (older two-field form)

    Version comes from either ``version = "..."`` (inline literal) or
    ``version.ref = "..."`` (alias into ``[versions]``); the
    alias-target lookup is one level deep and returns the literal
    ``${ref:...}`` placeholder when the ref isn't declared so the
    rule layer can still flag it as a dynamic / unresolved spec.

    Skips bundles (``[bundles]``) and plugins (``[plugins]``)
    deliberately, bundles point at multiple libraries (the per-
    library entries they reference are already in the index), and
    plugin references reach the dependency surface only through
    the ``plugins { }`` block, not ``dependencies { }``.
    """
    out: VersionCatalog = {}
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return out
    if not isinstance(raw, dict):
        return out
    versions_block = raw.get("versions")
    versions: dict[str, str] = {}
    if isinstance(versions_block, dict):
        for vname, vvalue in versions_block.items():
            if isinstance(vname, str) and isinstance(vvalue, str):
                versions[vname] = vvalue
            elif isinstance(vname, str) and isinstance(vvalue, dict):
                # Rich version constraint: ``strictly``, ``require``,
                # ``prefer``. Pick the first one present so MVN-001
                # sees a literal rather than a struct.
                for key in ("strictly", "require", "prefer"):
                    v = vvalue.get(key)
                    if isinstance(v, str):
                        versions[vname] = v
                        break
    libraries = raw.get("libraries")
    if not isinstance(libraries, dict):
        return out
    for name, entry in libraries.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        group, artifact = _catalog_coord(entry)
        if not group or not artifact:
            continue
        version = _catalog_version(entry, versions)
        if not version:
            continue
        # Normalize the catalog entry name to the DSL accessor.
        # Gradle converts any of ``-``, ``_`` to ``.`` so the catalog
        # aliases ``junit-jupiter``, ``junit_jupiter``, and the
        # already-dotted ``junit.jupiter`` all become the same DSL
        # accessor ``libs.junit.jupiter``.
        dsl_name = name.replace("-", ".").replace("_", ".")
        out[dsl_name] = (group, artifact, version)
    return out


def _catalog_coord(entry: dict[str, Any]) -> tuple[str, str]:
    """Return ``(group, artifact)`` from a catalog ``[libraries]`` entry."""
    module = entry.get("module")
    if isinstance(module, str) and ":" in module:
        head, _, tail = module.partition(":")
        return head.strip(), tail.strip()
    group = entry.get("group")
    name = entry.get("name")
    if isinstance(group, str) and isinstance(name, str):
        return group.strip(), name.strip()
    return "", ""


def _catalog_version(
    entry: dict[str, Any], versions: dict[str, str],
) -> str:
    """Return the version literal for one ``[libraries]`` entry.

    Resolves ``version.ref`` aliases against the ``[versions]`` map.
    Unknown refs emit the ``${ref:...}`` placeholder so MVN-001 still
    sees a non-literal version and fires.
    """
    version = entry.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict):
        ref = version.get("ref")
        if isinstance(ref, str):
            return versions.get(ref, f"${{ref:{ref}}}")
        for key in ("strictly", "require", "prefer"):
            v = version.get(key)
            if isinstance(v, str):
                return v
    return ""


def _discover_gradle_version_catalog(
    gradle_path: Path, scan_root: Path,
) -> VersionCatalog:
    """Walk upward from *gradle_path* looking for
    ``gradle/libs.versions.toml``; return the merged catalog.

    The conventional layout puts the catalog at
    ``<root>/gradle/libs.versions.toml``; the walk replicates the
    scan-root-bounded upward search used for ``gradle.properties``
    so subprojects pick up the root-level catalog without leaking
    out-of-tree reads.
    """
    out: VersionCatalog = {}
    try:
        scan_resolved = scan_root.resolve()
        cur = gradle_path.resolve().parent
    except OSError:
        return out
    seen_dirs: set[Path] = set()
    chain: list[Path] = []
    while True:
        if cur in seen_dirs:
            break
        seen_dirs.add(cur)
        chain.append(cur)
        if cur == scan_resolved:
            break
        parent = cur.parent
        if parent == cur:
            break
        try:
            cur.relative_to(scan_resolved)
        except ValueError:
            break
        cur = parent
    for d in reversed(chain):
        catalog_file = d / "gradle" / "libs.versions.toml"
        if not catalog_file.is_file():
            continue
        try:
            text = catalog_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        out.update(_parse_versions_catalog(text))
    return out


def _discover_gradle_cross_file_properties(
    gradle_path: Path, scan_root: Path,
) -> dict[str, str]:
    """Walk upward from *gradle_path*'s parent looking for sibling
    ``gradle.properties`` files; return the merged property map.

    Closest-to-the-script file wins on conflict (subproject overrides
    root). Walk stops at *scan_root* so a scan rooted in a subdir
    doesn't accidentally read ``~/.gradle/gradle.properties`` or
    other ancestors outside the scanned tree.

    The user-home ``~/.gradle/gradle.properties`` (Gradle's
    well-known global override location) is deliberately NOT read;
    pipeline-check stays a hermetic, repo-only scanner.
    """
    out: dict[str, str] = {}
    try:
        scan_resolved = scan_root.resolve()
        cur = gradle_path.resolve().parent
    except OSError:
        return out
    seen_dirs: set[Path] = set()
    # Walk in farthest-ancestor-first order so closer files (later
    # in the loop) overwrite farther ones, matching Gradle's
    # subproject-overrides-root semantics.
    chain: list[Path] = []
    while True:
        if cur in seen_dirs:
            break
        seen_dirs.add(cur)
        chain.append(cur)
        if cur == scan_resolved:
            break
        parent = cur.parent
        if parent == cur:
            break
        # Stop walking once we'd leave the scan root.
        try:
            cur.relative_to(scan_resolved)
        except ValueError:
            break
        cur = parent
    for d in reversed(chain):
        props_file = d / "gradle.properties"
        if not props_file.is_file():
            continue
        try:
            text = props_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        out.update(_parse_gradle_properties(text))
    return out


def _resolve_gradle_version(version: str, properties: dict[str, str]) -> str:
    """Substitute ``$prop`` / ``${prop}`` references in *version*.

    Single pass, no recursion: a property whose value itself contains
    another reference stays half-resolved. Real Gradle scripts almost
    never chain references at this depth; keeping the substitution
    flat keeps the rule pack deterministic.
    """
    if "$" not in version:
        return version

    def _sub(match: re.Match[str]) -> str:
        name = match.group("name")
        return properties.get(name, match.group(0))

    return _GRADLE_VERSION_REF_RE.sub(_sub, version)


def _line_at(text: str, offset: int) -> int:
    """1-based line number for a byte offset into *text*."""
    if offset < 0:
        return 1
    return text[:offset].count("\n") + 1


def _parse_gradle(
    path: str,
    text: str,
    extra_properties: dict[str, str] | None = None,
    version_catalog: VersionCatalog | None = None,
) -> PomFile:
    """Parse a ``build.gradle`` / ``build.gradle.kts`` body.

    Returns a :class:`PomFile` whose ``dependencies`` carry every
    matched coordinate + map-form dep (all marked ``managed=False``
    since Gradle has no direct analog of Maven's
    ``<dependencyManagement>`` lift-out — version catalogs / BOMs
    are a follow-up), and whose ``repositories`` carry every
    ``maven { url ... }`` URL found in the file. Built-in repo
    shorthand (``mavenCentral()``, ``google()``, ``gradlePluginPortal()``)
    is omitted from ``repositories`` because the rule pack doesn't
    flag them and their URLs are well-known.

    *extra_properties* feeds cross-file values (sibling
    ``gradle.properties``) into the substitution pass. In-file
    declarations override the cross-file map because Gradle's
    in-script extensions win against ``gradle.properties`` at
    runtime; the merge order here matches that semantic.

    ``parsed_ok`` is always True: the regex extractor never fails,
    a file with no matches simply returns an empty PomFile.
    """
    dependencies: list[MavenDependency] = []
    repositories: list[MavenRepository] = []
    seen_coords: set[tuple[str, str, str | None]] = set()
    seen_urls: set[str] = set()
    properties = dict(extra_properties) if extra_properties else {}
    properties.update(_extract_gradle_properties(text))

    for m in _GRADLE_COORD_RE.finditer(text):
        version = _resolve_gradle_version(m.group("version"), properties)
        coord = (m.group("group"), m.group("artifact"), version)
        if coord in seen_coords:
            continue
        seen_coords.add(coord)
        dependencies.append(MavenDependency(
            group_id=coord[0],
            artifact_id=coord[1],
            version=coord[2],
            scope="compile",
            managed=False,
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAP_DEP_WINDOW_RE.finditer(text):
        window = m.group(0)
        g = _GRADLE_MAP_GROUP_RE.search(window)
        a = _GRADLE_MAP_NAME_RE.search(window)
        v = _GRADLE_MAP_VERSION_RE.search(window)
        if not (g and a and v):
            continue
        version = _resolve_gradle_version(v.group("value"), properties)
        coord = (g.group("value"), a.group("value"), version)
        if coord in seen_coords:
            continue
        seen_coords.add(coord)
        dependencies.append(MavenDependency(
            group_id=coord[0],
            artifact_id=coord[1],
            version=coord[2],
            scope="compile",
            managed=False,
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAVEN_URL_RE.finditer(text):
        url = m.group("url")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        repositories.append(MavenRepository(
            id="",
            url=url,
            releases_enabled=True,
            snapshots_enabled=False,
            checksum_policy=None,
            section="repositories",
            line_no=_line_at(text, m.start()),
        ))

    for m in _GRADLE_MAVEN_SHORT_RE.finditer(text):
        url = m.group("url")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        repositories.append(MavenRepository(
            id="",
            url=url,
            releases_enabled=True,
            snapshots_enabled=False,
            checksum_policy=None,
            section="repositories",
            line_no=_line_at(text, m.start()),
        ))

    # ── Version-catalog references ──────────────────────────────────
    # Scan for ``<config> libs.<dot.path>`` shapes per line and
    # synthesize a MavenDependency from the catalog when the
    # accessor resolves. Lines that don't match a known dep
    # configuration (or whose path lands in ``libs.versions.*`` /
    # ``libs.bundles.*`` / ``libs.plugins.*`` namespaces) are
    # skipped so we don't materialize phantom deps.
    if version_catalog:
        # Track each line's start offset as we iterate so duplicate
        # catalog-reference lines (the common case in monorepos where
        # multiple subprojects share an identical ``testImplementation
        # libs.junit`` declaration) get their actual line number,
        # not the first occurrence's.
        offset = 0
        for line in text.splitlines(keepends=True):
            line_offset = offset
            offset += len(line)
            if not _GRADLE_CATALOG_LINE_RE.search(line):
                continue
            for cm in _GRADLE_CATALOG_REF_RE.finditer(line):
                head = cm.group("head")
                rest = cm.group("rest") or ""
                if head in ("versions", "bundles", "plugins"):
                    continue
                dotted = head + rest
                resolved = version_catalog.get(dotted)
                if resolved is None:
                    # Path may include a trailing accessor that
                    # isn't part of the catalog entry name (e.g.
                    # ``.get()``); try progressive prefix lookups.
                    parts = dotted.split(".")
                    for n in range(len(parts), 0, -1):
                        prefix = ".".join(parts[:n])
                        if prefix in version_catalog:
                            resolved = version_catalog[prefix]
                            break
                if resolved is None:
                    continue
                group_id, artifact_id, version = resolved
                coord = (group_id, artifact_id, version)
                if coord in seen_coords:
                    continue
                seen_coords.add(coord)
                dependencies.append(MavenDependency(
                    group_id=group_id,
                    artifact_id=artifact_id,
                    version=version,
                    scope="compile",
                    managed=False,
                    line_no=_line_at(text, line_offset),
                ))

    return PomFile(
        path=path,
        text=text,
        is_settings=False,
        dependencies=tuple(dependencies),
        repositories=tuple(repositories),
        mirrors=(),
        properties=properties,
        parsed_ok=True,
    )


# ── Helpers shared by multiple rule modules ────────────────────────────


def resolve_version(version: str, properties: dict[str, str]) -> str:
    """Expand a single ``${prop}`` reference using the POM's properties.

    Maven supports nested substitution, but a single level handles
    the overwhelming majority of real-world POMs and keeps the rule
    pack deterministic. Returns the unresolved literal when the
    referenced property isn't declared (so the rule sees the raw
    ``${...}`` form and can decide how to handle it).
    """
    v = version.strip()
    if not (v.startswith("${") and v.endswith("}")):
        return v
    key = v[2:-1]
    return properties.get(key, v)


def iter_real_dependencies(pom: PomFile) -> list[MavenDependency]:
    """Return every non-managed dependency entry."""
    return [d for d in pom.dependencies if not d.managed]


def iter_resolved_coordinates(pom: PomFile) -> list[tuple[str, str, str]]:
    """Return every ``(group_id, artifact_id, resolved_version)`` triple.

    Skips ``<dependencyManagement>`` entries (those are version-
    management declarations, not real consumption); skips dependencies
    with no ``<version>`` (resolved by parent BOM, the registry-side
    cooldown rule can't act on a coordinate it can't query); resolves
    a single level of ``${prop}`` substitution against the POM's
    ``<properties>`` block so ``${log4j.version}`` becomes the
    literal the registry actually carries. Unresolved ``${...}``
    references drop on the floor.
    """
    out: list[tuple[str, str, str]] = []
    for dep in iter_real_dependencies(pom):
        if dep.version is None:
            continue
        resolved = resolve_version(dep.version, pom.properties)
        if not resolved or resolved.startswith("${"):
            continue
        if not dep.group_id or not dep.artifact_id:
            continue
        out.append((dep.group_id, dep.artifact_id, resolved))
    return out


__all__ = [
    "GRADLE_NAMES",
    "MANIFEST_NAMES",
    "MavenBaseCheck",
    "MavenContext",
    "MavenDependency",
    "MavenMirror",
    "MavenRepository",
    "PomFile",
    "SETTINGS_NAMES",
    "iter_real_dependencies",
    "iter_resolved_coordinates",
    "resolve_version",
]
