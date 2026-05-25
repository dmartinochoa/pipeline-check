# pypi provider

Parses pip ``requirements*.txt`` / ``*.in`` files on disk for
supply-chain hygiene. Text-only static analysis, no ``pip install``,
no PyPI API access, no resolver run. Rule modules see a
``RequirementsFile`` (parsed lines + top-level options) and flag the
patterns that produced the dependency-confusion (Birsan 2021),
typosquat (PyTorch ``torchtriton`` 2022), and TLS-bypass
historical incidents.

## Producer workflow

```bash
# --pypi-path is auto-detected when requirements.txt exists at cwd.
pipeline_check --pipeline pypi

# …or pass it explicitly.
pipeline_check --pipeline pypi --pypi-path requirements.txt

# Recursively scan a project tree: every requirements*.txt and *.in
# under the path is picked up.
pipeline_check --pipeline pypi --pypi-path .
```

## Scope

* ``requirements.txt`` (and any ``requirements*.txt`` variant)
* ``requirements/*.txt`` (split-by-environment layout)
* ``*.in`` (pip-tools input files)

``pyproject.toml`` (PEP 621 / Poetry), ``Pipfile.lock``, and
``poetry.lock`` are out of scope for the initial pack and queued for
a follow-up. Most of the strongest supply-chain signals — pinning,
hashing, ``--extra-index-url`` confusion, ``--trusted-host`` —
live in the requirements file the build actually feeds to pip, which
this provider covers.

## ``*.in`` exemptions

``*.in`` files are pip-tools *inputs*: declarative ranges that get
compiled (via ``pip-compile``) into resolved, hash-bearing
``requirements.txt`` outputs. PYPI-001 (pin) and PYPI-002 (hash) are
intentionally skipped on ``.in`` files — pinning at the input layer
is the wrong layer. The rules still fire on the compiled
``requirements.txt`` so the artifact pip actually installs is
covered.

## What it covers

8 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [PYPI-001](#pypi-001) | requirements.txt entry missing an exact version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PYPI-002](#pypi-002) | requirements.txt missing hash pinning (--require-hashes / --hash=) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-003](#pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-004](#pypi-004) | requirements.txt VCS dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-005](#pypi-005) | requirements.txt declares --extra-index-url (dependency-confusion surface) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-006](#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [PYPI-008](#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-009](#pypi-009) | PyPI package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## PYPI-001: requirements.txt entry missing an exact version pin { #pypi-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires on any requirement that does not use ``==`` to pin a single version, including:

* Bare names (``requests``)
* Range specifiers (``django>=4,<5``, ``urllib3~=2.0``)
* Lone upper-bound (``packaging<24``)

Skips VCS specs (``git+https://...``), URL specs (``https://example.com/foo.tar.gz``), editable installs (``-e .``), and local paths (``./packages/foo``) — those have different pinning shapes and are handled by PYPI-004 or fall outside the version-pinning surface. Complements PYPI-002 (hash pinning) and PYPI-004 (VCS commit pin); PYPI-001 is the version-name layer.

**Known false-positive modes**

- Files that are pip-tools *inputs* (``requirements.in``) carry unpinned ranges by design, the resolved ``*.txt`` is the artifact pip installs. If you're scanning a ``*.in`` file intentionally, suppress with a rationale naming the compiled output.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every requirement to an exact version (``foo==1.2.3``). Range specifiers (``>=``, ``~=``, ``<``) and unpinned names let pip pick a later release on the next install, so a compromised patch version (PyTorch typosquat, ctx package, request-PR worm) reaches the build without a code change. Generate the file with ``pip-compile`` to lock the full transitive set, and pair the pin with ``--require-hashes`` (PYPI-002) so the lock is verified at install time.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-002: requirements.txt missing hash pinning (--require-hashes / --hash=) { #pypi-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires when:

* The file does not declare ``--require-hashes`` at the top, AND
* At least one requirement line is missing a ``--hash=...`` flag.

When ``--require-hashes`` is present, pip enforces hash pinning for every requirement and itself refuses the install if any line is missing a ``--hash``; the rule still flags any line that visibly lacks the flag so the doc reader sees the actual coverage. ``*.in`` (pip-tools input) files are exempt — they're declarative inputs, the compiled ``*.txt`` is the hash-bearing artifact pip installs. Complements PYPI-001 (version pin); PYPI-002 is the layer that catches an attacker swapping the artifact even when the version literal is unchanged.

**Known false-positive modes**

- Files generated by ``poetry export`` historically wrote hashes without ``--require-hashes`` at the top, which looks unpinned but is enforced by Poetry's own resolver in CI. Add the top-level ``--require-hashes`` to the exported file (or replace ``poetry export`` with ``pip-compile --generate-hashes``) so the requirements file is self-describing.

**Seen in the wild**

- PyTorch dependency confusion (December 2022): the ``torchtriton`` name on PyPI was claimed by a malicious publisher and pulled in via a nightly build, exfiltrating SSH keys and ``/etc/passwd``. Hash pinning would have rejected the unexpected artifact regardless of which registry resolved the name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Regenerate the file with ``pip-compile --generate-hashes`` (pip-tools) or ``pip hash`` and add ``--require-hashes`` at the top. Every requirement line then carries one or more ``--hash=sha256:...`` entries pinning the artifact bytes pip downloads. ``--require-hashes`` forces pip to refuse installs that don't match, closing the window where a compromised registry (or a malicious mirror, or a MITM on an internal proxy) swaps the tarball/wheel without your lockfile changing.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-003: requirements.txt uses an HTTP index or disables TLS verification { #pypi-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Fires when the file's top-level options include:

* ``--index-url http://...`` / ``-i http://...``
* ``--extra-index-url http://...``
* ``--trusted-host <host>``

Complements DF-021 (Dockerfile ``RUN pip install ``-i http://...``); PYPI-003 catches the same pattern when it's baked into the requirements file rather than the shell command. Note ``--trusted-host`` also weakens PYPI-002 — pip silently skips hash checking for the trusted host even when ``--require-hashes`` is set.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch ``--index-url`` and ``--extra-index-url`` to ``https://`` and remove ``--trusted-host``. If your internal index has a self-signed certificate, install the CA into the build environment's truststore (or pass ``PIP_CERT=/path/to/ca.pem``) instead of telling pip to skip verification. ``--trusted-host`` disables TLS verification *and* hash verification for the named host, so anyone on the network path can swap the wheel.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-004: requirements.txt VCS dependency uses a mutable ref { #pypi-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires on requirement lines whose URL is a VCS scheme (``git+https://``, ``git+ssh://``, ``hg+``, ``svn+``, ``bzr+``) and whose ``@<ref>`` segment is not a 40-character SHA. A line with no ``@<ref>`` at all also fires — that resolves to the default branch HEAD, the most mutable form. Note: ``foo @ git+https://...`` (PEP 508 direct URL) and ``-e git+https://...#egg=foo`` (legacy editable install) are both detected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin VCS requirements to a 40-character commit SHA: ``foo @ git+https://github.com/owner/repo.git@<sha>`` (or the legacy ``-e git+...@<sha>#egg=foo`` form). Branch and tag refs (``@main``, ``@v1.2.3``) are mutable, anyone with push access to the upstream repo can swap the contents of what your build pulls without changing the requirement line. A 40-char SHA is immutable. If the upstream isn't yours, prefer vendoring a fork into a private index and pinning by version + hash (PYPI-001 / PYPI-002).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-005: requirements.txt declares --extra-index-url (dependency-confusion surface) { #pypi-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-427</span>
</div>

Fires when the file declares ``--extra-index-url`` at any level. The flag itself is the anti-pattern, the URL value doesn't matter, pip will query both the primary and the extra index for every package and pick the higher version. An attacker who registers a public PyPI package with the same name as an internal-only dependency wins the version comparison and ships their code into the build.

If the extra index is a hash-locked internal proxy that serves *both* internal and mirrored-public packages, consolidating it into the primary ``--index-url`` removes the surface without losing any capability. Suppress with a rationale only when both indexes share an operator-controlled allow-list of names.

**Seen in the wild**

- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021): internal package names harvested from public-facing manifests were registered on public PyPI / npm with higher version numbers; victim builds that declared the public index as an extra automatically pulled the attacker's package on the next install.
- PyTorch ``torchtriton`` (December 2022): a typosquat name on PyPI's public index was preferred over the internal nightly build, exfiltrating SSH keys via a postinstall step. Single-index installations were unaffected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``--extra-index-url`` with a single ``--index-url`` pointing at the index you actually want (an internal proxy or a curated private index), and configure that index to transparently mirror PyPI for any package not published internally. With ``--extra-index-url``, pip queries *both* indexes for every name and picks the highest version — so a public PyPI publisher who registers your internal package name (``acme-internal``) with a higher version wins the resolution. The single-index pattern eliminates the dependency-confusion vector entirely.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## PYPI-006: requirements.txt pins a known-compromised PyPI package version { #pypi-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Walks every ``name==version`` line in the requirements file against the curated compromised-package registry in ``pipeline_check.core.checks.pypi._compromised_packages``. Name matching follows PEP 503 normalization (lowercase, underscore/dot folded to hyphen) so ``Pillow``, ``pillow``, and ``Pil_Low`` resolve to the same registry entry. Lines without an exact ``==`` pin can't be evaluated by this rule (the version literal isn't decidable from the file alone); those are PYPI-001's surface. VCS URLs and local / editable installs are skipped — they don't carry a registry-resolvable version. Registry is hand-curated and append-only; refresh by PR with the citing advisory.

**Known false-positive modes**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing advisory exists. For broader coverage, run ``pip-audit`` or ``osv-scanner`` alongside pipeline-check; PYPI-006 is the curated supply-chain anchor, not a vulnerability database.

**Seen in the wild**

- ctx package compromise (May 2022): the abandoned ``ctx`` package was claimed by an attacker and republished with an env-var exfiltration payload targeting AWS keys / GitHub tokens. https://isc.sans.edu/diary/28772
- requests-darwin-lite 2.27.1 ([GHSA-7gjg-3qcj-9jvg](https://github.com/advisories/GHSA-7gjg-3qcj-9jvg), May 2024): typosquat-flavored package whose wheel embedded the Geneva malware framework.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate every secret reachable to any process that ran ``pip install`` against this requirements file during the window the compromised version was installed (AWS keys, GH tokens, SSH keys — most published PyPI compromises have been credential stealers). Bump the affected requirement to a post-incident clean version published after the maintainer / PyPI took down the malicious release, and audit CI logs for the exfiltration shape the advisory documents. Pair with PYPI-002 (``--require-hashes``) so a future swap of the same version literal fails verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-008: Direct dependency was published within the cooldown window { #pypi-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to populate the per-package publish timestamps from the PyPI JSON API (``https://pypi.org/pypi/<name>/json``). Walks every exact-version requirement (``foo==1.2.3``) and flags ones whose newest file record landed within the cooldown window (default 7 days). Range specs (``foo>=1.2``, ``foo~=1.2``), unpinned specs, VCS / URL / editable lines, and dist-tag-style specs are out of scope — the cooldown applies to a specific version literal because that's what the maintainer chose to pin. When ``--resolve-remote`` is off or the registry can't be reached, the rule passes silently so the absence of the network path doesn't trip CI.

**Known false-positive modes**

- Pre-release versions (``foo==1.0.0rc1``) are often freshly published; the cooldown applies to them too because pre-release tags have been used as carriers in real compromises. Suppress per-resource via ``--ignore-file`` when a release-train workflow legitimately pins to a same-day RC.
- Same-day patch upgrades from a maintainer the team directly trusts (e.g. a vendored fork the team owns) are flagged. Suppress per-resource — the cooldown is a default-safe gate, not a hard rule.

**Seen in the wild**

- ctx package compromise (May 2022): the abandoned ``ctx`` package was claimed by an attacker and republished with an env-var exfiltration payload. The malicious 0.2.x versions stayed live until PyPI yanked them ~24h later. Consumers who held a 7-day cooldown caught the takedown before installing.
- requests-darwin-lite 2.27.1 ([GHSA-7gjg-3qcj-9jvg](https://github.com/advisories/GHSA-7gjg-3qcj-9jvg), May 2024): typosquat-flavored package whose wheel embedded the Geneva malware framework. The malicious version was live for less than 48 hours before disclosure and yank.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either skip the just-published version (pin to the last release older than the cooldown window) or wait until the cooldown has elapsed before bumping the requirements file. Most publisher-account compromises on PyPI (``ctx`` 2022, ``requests-darwin-lite`` 2024, ``ultralytics`` 2024, the ``rspack`` / ``vant`` / ``nx`` / ``@ctrl/*`` campaigns) are detected and yanked from the index within hours-to-days of publication; holding back N days converts a publisher-compromise window into a vulnerability-disclosure window where either the maintainer rotates the malicious version off the index or the security community files an advisory that PYPI-006 can match against.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## PYPI-009: PyPI package has a known OSV advisory { #pypi-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Network-dependent: needs ``--resolve-remote`` to query the OSV advisory database (``api.osv.dev``). Passes silently when the flag is off. Complements PYPI-006 (curated offline registry) with the full OSV/GHSA long-tail.

<div class="pg-rule__rec" markdown>

**Recommended action**

Upgrade to a patched version or remove the affected package. Consult the advisory URL for remediation guidance.

</div>

</div>

---

## Adding a new pypi check

1. Create a new module at
   `pipeline_check/core/checks/pypi/rules/pypiNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(rf: RequirementsFile) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``RequirementsFile``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/pypi/PYPI-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py pypi
   ```
