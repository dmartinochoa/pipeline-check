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

19 checks · 0 have an autofix patch (``--fix``).

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
| [PYPI-010](#pypi-010) | Requirements file carries an index URL with embedded credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-011](#pypi-011) | Requirements file disables TLS verification via --trusted-host | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-012](#pypi-012) | pyproject.toml [build-system].requires uses floating versions | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-013](#pypi-013) | pyproject.toml defers dependency resolution via dynamic | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PYPI-014](#pypi-014) | Custom package source in pyproject.toml uses plain HTTP | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PYPI-015](#pypi-015) | requirements.txt installs from a direct artifact URL | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-016](#pypi-016) | requirements.txt repoints the primary index at a non-PyPI host | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PYPI-017](#pypi-017) | requirements.txt uses a remote --find-links source | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PYPI-018](#pypi-018) | requirements.txt forces source builds via --no-binary | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PYPI-019](#pypi-019) | Direct dependency published without PEP 740 provenance | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [PYPI-020](#pypi-020) | Direct dependency has a low OpenSSF Scorecard | <span class="pg-sev pg-sev--low">LOW</span> |  |

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

<div class="pg-rule pg-rule--high" markdown>

## PYPI-010: Requirements file carries an index URL with embedded credentials { #pypi-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads top-level ``--index-url`` / ``--extra-index-url`` / ``-i`` options from each requirements file and fires when the URL's authority component carries an ``<user>:<pass>@`` prefix. Empty-password forms (``https://user:@host``) and ``${VAR}`` placeholders are skipped — the former is operator-flagged as 'no credential intended' and the latter resolves at install time from the environment rather than the manifest text.

Mirrors NPM-013-style risks for npm's ``.npmrc`` ``_authToken`` but adapted to pip's URL-embedded form. The npm rule has a dedicated registry-token slot; pip and poetry leak the credential at the URL level instead.

**Known false-positive modes**

- Internal templating tools that emit a placeholder credential form (``https://__TOKEN__:@my.org``) and substitute the real value at install time trip this rule by shape. Suppress per file when the template marker is stable; the rule's placeholder skip-list only recognizes ``${...}``.

**Seen in the wild**

- Long-running pattern of internal artifact-registry credentials leaking through requirements files committed to public mirrors. The credential's audit trail (last rotated, who has it) is lost the moment the file lands in a clone an attacker controls; the cost is rotation plus follow-up reviews of every system that used the leaked credential during the exposure window.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential out of the URL and into the environment or a dedicated config file the host respects:

* Set ``PIP_INDEX_URL=https://my.org/simple`` and pass the credentials via ``PIP_KEYRING_PROVIDER=subprocess`` plus ``~/.config/pip/pip.conf`` (which lives outside the repo).
* For poetry, use ``poetry config http-basic.<repo-name> <user> <pass>`` so credentials land in the user's keyring rather than the manifest.
* For CI runners, inject the credentials at install time via ``PIP_INDEX_URL=https://${TOKEN}@my.org/simple`` from a CI secret variable and never commit the resolved form.

Credentials embedded in a committed ``--index-url`` flag lock the password into git history. The value persists in every clone, every CI cache, and every backup; rotation requires consumer-side updates *plus* history scrub before the leaked credential stops being useful to an attacker.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-011: Requirements file disables TLS verification via --trusted-host { #pypi-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``--trusted-host`` options from each requirements file and fires once per declared host. The flag's semantics are exactly the named-host TLS bypass: certificate validation is skipped, the certificate's expiry / signature / SAN are not consulted, and a MITM that intercepts the TCP connection to the named host can serve arbitrary wheel content without raising pip's verification.

Distinct from PYPI-003 (HTTP index URL) and PYPI-005 (``--extra-index-url`` to a non-default registry): those rules catch the configuration shapes that *declare* an insecure source, this one catches the explicit-bypass shape that disables the verification that would otherwise gate the install.

**Known false-positive modes**

- A small number of internal mirrors that legitimately operate on HTTP within a strictly-firewalled network use ``--trusted-host`` as a deliberate posture. The rule still fires; suppress per host with a one-line rationale naming the network boundary that justifies skipping TLS.

**Seen in the wild**

- Long-running pattern in CI debugging sessions: a transient certificate problem on an internal mirror is worked around by adding ``--trusted-host`` to requirements.txt, the certificate is fixed days later, the flag is never removed. The bypass persists indefinitely; every subsequent ``pip install`` against that requirements file accepts unauthenticated wheel content.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove every ``--trusted-host`` flag from the requirements file and fix the underlying TLS problem instead. The flag tells pip to skip certificate validation for the named host, which means any MITM along the install path can swap the wheel without detection. Three remediation patterns:

* If the host is internal and has a valid certificate signed by a private CA, distribute the CA bundle to consumers (``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE``) and drop the flag.
* If the host serves plain HTTP, switch to HTTPS — most internal artifact registries ship with a built-in self-signed certificate that's easy to swap for a real one.
* If the host is genuinely external and the certificate is expired (common with abandoned mirrors), switch to the canonical PyPI URL or a maintained mirror.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-012: pyproject.toml [build-system].requires uses floating versions { #pypi-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Re-parses each ``pyproject.toml`` (or ``pyproject.toml`` synthesized into the requirements view) and inspects ``[build-system].requires`` for entries without an exact ``==X.Y.Z`` pin. Caret (``^``), tilde (``~``), comparison (``>=`` / ``<``), wildcard (``*``), and unbounded (``setuptools``) all trip the rule.

Distinct from PYPI-001 (general missing-pin), which audits every dependency table in the same view. This rule scopes to the build-system requires specifically because the build-time install hook surface is higher-risk than runtime deps: the latter at least have a chance to be caught by a sandboxed CI test before they ship; the former runs at ``pip install`` time, before any test ever executes.

**Known false-positive modes**

- Some library projects deliberately leave ``setuptools>=64`` unbounded so downstream consumers can pick a compatible patch automatically. The rule still fires; suppress per file with a one-line rationale naming the publish-time intent. Application repos (not libraries) should pin.

**Seen in the wild**

- Build-time compromise pattern: a popular ``setuptools`` patch release ships with a poisoned post-install hook that executes during every downstream ``pip install``. Floating build-system requires inherit the malicious version automatically; exact pins survive the incident until the consumer chooses to bump. The xz-utils style patch-release smuggle pattern works on every ecosystem with floating build-time deps, not just system packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every entry in ``[build-system].requires`` to an exact version (``setuptools==69.0.2``, ``wheel==0.42.0``). Build-system requirements differ from runtime dependencies in one critical way: they run during package installation — ``setup.py``, ``setup.cfg``, ``pyproject.toml``-driven build hooks — before any runtime sandbox is in place. A compromised ``setuptools`` patch release executes arbitrary Python in the install environment and inherits whatever privileges the install process has (CI runner write access, deploy keys, AWS credentials in the environment).

After exact-pinning the build-system requires, audit the pins quarterly: subscribe to ``setuptools`` / ``wheel`` GHSA feeds, dependabot-style automated bumps, and consider running ``pip install --no-build-isolation`` against a pre-warmed wheel cache so the build environment is reproducible across runs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PYPI-013: pyproject.toml defers dependency resolution via dynamic { #pypi-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Re-parses ``pyproject.toml`` and inspects ``[project].dynamic`` for entries that defer dependency resolution: ``"dependencies"`` and ``"optional-dependencies"`` specifically (other dynamic fields like ``"version"`` are also flagged but at informational priority — they don't affect supply-chain audit, just hygiene).

The rule's value is closing a static-analysis blind spot: a project that lists no dependencies in ``[project].dependencies`` while declaring ``dynamic = ["dependencies"]`` looks dependency-free to PYPI-001 / PYPI-002 / PYPI-008, but ships with a full real-world dependency graph that was computed at build time.

**Known false-positive modes**

- Some libraries use ``dynamic = ["version"]`` with ``setuptools_scm`` legitimately so a single source of truth (a git tag) drives both the package version and the changelog. The version-only case is the lowest-impact form; suppress per file with a one-line rationale naming the scm-driven version policy. The ``dependencies`` / ``optional-dependencies`` cases should not be suppressed without static-analysis parity evidence.

**Seen in the wild**

- Static-analysis blind-spot class commonly surfaced in audits of libraries that ship pyproject.toml as a modern facade over a legacy setup.py: the manifest looks PEP 621-compliant but ``dynamic = ["dependencies"]`` punts the real list to ``setup.py``, which can do anything (read environment variables, fetch lists over the network, derive deps from a config file in the repo). Every supply-chain audit downstream has to know setup.py's dynamic behavior to be accurate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move every entry out of ``[project].dynamic`` and into an explicit static field on ``[project]``. ``dynamic`` tells the build backend to compute the value at build time, typically by reading ``setup.py`` / ``setup.cfg`` / a vendor-specific extension. Static analysis can't see those values, which means every linter, IDE, SBOM-generator, and supply-chain scanner (this one included) is blind to the dependency set.

The migration is mechanical:

* ``dynamic = ["dependencies"]`` → move runtime deps into ``[project].dependencies`` as a static list.
* ``dynamic = ["optional-dependencies"]`` → move into ``[project.optional-dependencies]``.
* ``dynamic = ["version"]`` → if computed from ``__version__``, switch to a ``setuptools_scm``-style version-from-VCS configuration that's at least declared in the manifest, or commit to an explicit literal.

After the migration, this rule passes and PYPI-001 takes over for the floating-spec audit of the now-visible dependency list.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PYPI-014: Custom package source in pyproject.toml uses plain HTTP { #pypi-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Re-parses ``pyproject.toml`` and walks every custom package-source table for an HTTP URL. The Poetry, uv, and PDM source-list shapes are all covered; each one emits a separate finding per offending URL.

Pairs with PYPI-003 (HTTP index URL in requirements.txt) but at the modern-resolver layer. A project that's migrated off requirements.txt to pyproject.toml + a resolver-specific source list still needs the HTTPS audit; PYPI-003 doesn't see those entries because they live in a different table.

**Known false-positive modes**

- Local-development mirrors running on loopback HTTP (``http://localhost:8080``) are a common workaround for offline development. The rule still fires; suppress per file with a one-line rationale naming the dev-only use. Production / CI configurations should not be suppressed.

**Seen in the wild**

- Common MITM pattern: a CI runner installs from an internal Nexus declared in ``[[tool.poetry.source]]`` with an HTTP URL. The runner's network path is shared with other tenants (CI cluster, kubernetes namespace) that any of which can route traffic through a proxy that returns a tampered wheel. The HTTPS alternative would have caught the tampering at the TLS layer before pip ever saw the wheel content.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch the source URL to HTTPS for every custom registry declared in ``pyproject.toml``. The two common shapes are:

* Poetry: ``[[tool.poetry.source]]`` entries with a ``url = "http://..."`` value.
* uv: ``[tool.uv.sources]`` entries with an ``index = "http://..."`` or ``url = "http://..."`` value.
* PDM: ``[[tool.pdm.source]]`` entries with a ``url = "http://..."`` value.

Internal artifact registries (Nexus, Artifactory, devpi, private mirrors) ship with built-in HTTPS support; the switch is usually a one-line config change. After the switch, drop any ``--trusted-host`` workarounds the HTTP endpoint was hiding (see PYPI-011).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-015: requirements.txt installs from a direct artifact URL { #pypi-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires on a requirement whose spec is an ``http(s)`` artifact URL: the PEP 508 ``name @ https://...`` form and the bare ``https://host/foo.whl`` / ``foo.tar.gz`` / ``foo.zip`` direct-download form. VCS schemes (``git+``, ``hg+``, ``svn+``, ``bzr+``) are PYPI-004's surface and are skipped here. URLs pointing at canonical PyPI hosts (``pypi.org`` / ``files.pythonhosted.org``) are not flagged. A line that carries an inline ``--hash=`` is not flagged, the hash makes the direct download verifiable.

Complements PYPI-001 (which skips URL specs) and PYPI-004 (which only matches VCS schemes), closing the http(s)-artifact gap neither one sees.

**Known false-positive modes**

- An internal release server that publishes immutable, content-addressed artifacts may legitimately use direct URLs. Add an inline ``--hash`` to pin the bytes (which also silences this rule), or suppress per line with a rationale once the URL is verified out of band.

<div class="pg-rule__rec" markdown>

**Recommended action**

Install the package from an index by ``name==version`` (PYPI-001) with a recorded ``--hash`` (PYPI-002) instead of a direct artifact URL. A ``name @ https://host/foo.whl`` or a bare wheel / tarball URL pulls bytes from one host with no name, version, or hash gating, so a takeover of that host, or a swap of the file behind a stable URL, lands arbitrary code in the build. If a direct URL is genuinely unavoidable, pin it with an inline ``--hash=sha256:...`` so the downloaded bytes are verified, and serve it over HTTPS from a host you control.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PYPI-016: requirements.txt repoints the primary index at a non-PyPI host { #pypi-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Fires on a top-level ``--index-url`` / ``-i`` whose host is not ``pypi.org`` / ``files.pythonhosted.org``. PYPI-005 flags only the additive ``--extra-index-url``; this rule catches the substitutive vector, which is the more dangerous one because there is no PyPI source left to compare against.

Plain-HTTP index URLs are also PYPI-003 and inline-credential URLs are also PYPI-010; this rule is specifically about the primary index host being repointed at all. Hosts that look like internal mirrors (``*.internal``, ``*.corp``, ``*.local``, ``*.intra``, ``*.lan``, ``localhost``, an ``artifactory`` / ``nexus`` / ``devpi`` host, or a bare hostname with no dot) are treated as known false positives and skipped.

**Known false-positive modes**

- A legitimate corporate mirror or proxy is the intended index. The internal-mirror heuristic skips the common shapes (``pypi.internal``, ``artifactory.corp/...``, ``*.local`` / ``*.intra`` / ``*.lan`` hosts, ``localhost``, single-label hostnames). For a cloud-hosted private index that does not match the heuristic, suppress per file once the host is verified.

<div class="pg-rule__rec" markdown>

**Recommended action**

Point ``--index-url`` / ``-i`` at canonical PyPI (``https://pypi.org/simple``) or at a vetted internal mirror that proxies PyPI. ``--index-url`` (and the ``PIP_INDEX_URL`` environment form) replaces the default index outright, so every package, direct and transitive, is resolved from that one host. If the host is attacker-controlled or compromised, the whole dependency tree is served by it. Keep the chosen index under change control and pin every requirement with ``==`` (PYPI-001) and a ``--hash`` (PYPI-002) so a swapped index cannot silently change the bytes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PYPI-017: requirements.txt uses a remote --find-links source { #pypi-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a top-level ``--find-links`` / ``-f`` whose value is a remote ``http(s)`` URL. Local directory paths (``./vendor/wheels``, ``/opt/wheels``) carry no host and are not flagged. URLs on canonical PyPI hosts are not flagged.

Severity escalates from MEDIUM to HIGH when ``--no-index`` is also set in the same file (find-links becomes the only source pip uses, with no index to fall back on) or when the URL is plain ``http://`` (the download is tamperable in transit). ``--find-links`` was parsed before but unused; this rule is the consumer.

**Known false-positive modes**

- A ``--find-links`` to a vetted internal artifact host serving immutable, hashed files can be intentional. Pin the requirements with ``--hash`` and suppress per file once the host is verified.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve packages from a single trusted index instead of a remote ``--find-links`` URL. ``--find-links`` adds an extra place pip looks for distributions, and pip will install a wheel or sdist found there outside the normal index resolution, so the host becomes an unreviewed package source. If you must serve files this way, use an ``https://`` host you control and pin every requirement with ``==`` (PYPI-001) and a ``--hash`` (PYPI-002) so the bytes are verified regardless of where pip found them.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PYPI-018: requirements.txt forces source builds via --no-binary { #pypi-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on any top-level ``--no-binary`` option, including the ``--no-binary :all:`` form and the package-scoped ``--no-binary <name>`` form. The complementary ``--only-binary`` is the safer direction (it forbids source builds) and is not flagged.

This is the install-time code-execution surface that the wheel-only path avoids: pip building an sdist invokes the package's build backend, which is attacker-controlled code for any dependency whose source you don't audit.

**Known false-positive modes**

- Some packages ship only an sdist, or you compile a C extension against the build host on purpose. In that case the source build is intentional; scope ``--no-binary`` to the named package and suppress per file with a rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``--no-binary`` and install prebuilt wheels where possible. ``--no-binary`` tells pip to skip wheels and build from the source distribution, and an sdist build runs the package's ``setup.py`` (or PEP 517 backend) on the build machine, so installing the dependency executes arbitrary code at install time. A wheel install runs no package code, so this option widens the install-time code-execution surface. If a source build is genuinely required (a package with no wheel, or a C extension you must compile), scope ``--no-binary`` to the specific package rather than ``:all:``, and run the build in a sandboxed, network-isolated step with pinned, hashed requirements.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## PYPI-019: Direct dependency published without PEP 740 provenance { #pypi-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Network-dependent: needs ``--resolve-remote`` to read each direct dependency's latest-release attestation surface from the PyPI JSON API (the same per-package document the cooldown / OSV passes fetch, so it adds no extra requests). Reads the ``provenance`` field on the latest release's file records and flags a package whose files carry no populated provenance. Scoped to direct, index-resolved dependencies in the requirements files; URL / VCS / ``name @ url`` specs and transitive packages are out of scope.

LOW severity by design: PEP 740 attestation adoption across PyPI is still ramping, so the absence is common and this is an informational posture signal that stays below the default ``--fail-on`` gate. When ``--resolve-remote`` is off, the registry can't be reached, or the index doesn't expose the attestation field, the rule passes silently.

**Known false-positive modes**

- A distribution can be securely published without PEP 740 attestations (it may predate Trusted Publishing, or use a different signing scheme). The absence is a weaker signal than a present-but-invalid attestation would be. Suppress per-resource for dependencies whose supply chain the team has otherwise vetted.

**Seen in the wild**

- PEP 740 / PyPI digital attestations (GA November 2024): publishing via Trusted Publishing produces a signed, verifiable link from the PyPI artifact to the exact source commit and CI run, the property an attacker who republishes a tampered distribution cannot forge.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build provenance (PEP 740 attestations on PyPI) ties a published distribution back to the source repository and CI build that produced it, the same SLSA guarantee this project ships on its own wheel. A dependency whose latest release carries no attestation can't be cryptographically traced to its source, so a registry-side tamper or a look-alike republish is harder to detect. Prefer dependencies that publish with attestations where a maintained alternative exists, and ask upstreams you rely on to adopt Trusted Publishing with attestations (a one-line change to a GitHub Actions ``pypa/gh-action-pypi-publish`` job). This is a posture signal, not a defect in the dependency. The npm analog is NPM-015.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## PYPI-020: Direct dependency has a low OpenSSF Scorecard { #pypi-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Network-dependent: needs ``--resolve-remote``. The dependency's GitHub repo is resolved from its PyPI metadata (``info.project_urls`` / ``home_page``, the same per-package JSON document the cooldown / provenance passes read), then each repo is looked up against the OpenSSF Scorecard API (``api.securityscorecards.dev``), which is the one extra network surface this rule adds. Flags a dependency whose upstream repo scores below 5/10 or fails the Dangerous-Workflow check.

Scoped to direct, index-resolved dependencies. A package with no GitHub repo in its PyPI metadata, or one the Scorecard project hasn't indexed, is skipped. LOW severity, an informational upstream-posture signal below the default ``--fail-on`` gate; passes silently when ``--resolve-remote`` is off or the APIs can't be reached.

**Known false-positive modes**

- Scorecard scores a repo's *practices*, not whether a given release is malicious; a low score is a prior, not a verdict. Small but well-run projects can score low on checks that assume a larger team (code-review, CII-best-practices). Treat it as a prompt to look closer, and suppress per-resource for dependencies the team has vetted.

**Seen in the wild**

- OpenSSF Scorecard (securityscorecards.dev): the Dangerous-Workflow check specifically detects the ``pull_request_target`` + untrusted-checkout script-injection pattern behind multiple real CI compromises, so a failing score on a dependency's repo is a concrete, not abstract, weak-link signal.

<div class="pg-rule__rec" markdown>

**Recommended action**

A low OpenSSF Scorecard (or a failed Dangerous-Workflow check) on a direct dependency's own repository is a weak-link signal: the project lacks the maintenance and CI-hardening practices (branch protection, pinned actions, no ``pull_request_target`` script injection, code review) that make a compromise less likely and more detectable. Weigh a better-scored alternative where one exists, pin to a reviewed version, and for the ones you keep, watch them more closely (cooldown, provenance). This is an upstream-posture signal, not a defect you can fix in your own repo. The npm analog is NPM-016.

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
