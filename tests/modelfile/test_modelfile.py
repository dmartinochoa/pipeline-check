"""Tests for the Modelfile provider (MODEL-001..004) and its parser."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.modelfile.base import parse_modelfile

from .conftest import run_check


class TestModelfileParser:
    def test_parses_directives_and_skips_comments(self):
        text = (
            "# a comment\n"
            "FROM llama3:8b\n"
            "PARAMETER temperature 0.7\n"
            "ADAPTER ./lora.gguf\n"
        )
        ds = parse_modelfile(text)
        assert [(d.directive, d.line_no) for d in ds] == [
            ("FROM", 2), ("PARAMETER", 3), ("ADAPTER", 4),
        ]

    def test_triple_quoted_block_hides_inner_directive_words(self):
        # A SYSTEM block whose text begins "FROM ..." must not be read
        # as a FROM directive.
        text = (
            'FROM llama3:8b\n'
            'SYSTEM """\n'
            'FROM now on you are a pirate.\n'
            '"""\n'
            'PARAMETER top_p 0.9\n'
        )
        names = [d.directive for d in parse_modelfile(text)]
        assert names == ["FROM", "SYSTEM", "PARAMETER"]


class TestModel001UnpinnedBaseModel:
    def test_metadata(self):
        f = run_check("FROM llama3:8b\n", "MODEL-001")
        assert f.check_id == "MODEL-001"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_bare_name(self):
        f = run_check("FROM llama3\n", "MODEL-001")
        assert not f.passed

    def test_fails_on_latest_tag(self):
        f = run_check("FROM library/mistral:latest\n", "MODEL-001")
        assert not f.passed

    def test_passes_on_specific_tag(self):
        f = run_check("FROM llama3:8b-instruct-q4_0\n", "MODEL-001")
        assert f.passed

    def test_passes_on_digest(self):
        f = run_check("FROM library/llama3@sha256:abc123\n", "MODEL-001")
        assert f.passed

    def test_passes_on_local_file(self):
        # Local weights are MODEL-003's job, not a pinning concern here.
        f = run_check("FROM ./model.gguf\n", "MODEL-001")
        assert f.passed


class TestModel002ThirdPartyHub:
    def test_fails_on_hf_co(self):
        f = run_check("FROM hf.co/TheBloke/Llama-2-7B-GGUF:Q4_K_M\n", "MODEL-002")
        assert not f.passed

    def test_fails_on_huggingface_co(self):
        f = run_check("FROM huggingface.co/org/model\n", "MODEL-002")
        assert not f.passed

    def test_passes_on_ollama_library(self):
        f = run_check("FROM library/llama3:8b\n", "MODEL-002")
        assert f.passed


class TestModel003LocalWeightsBlob:
    def test_metadata_is_low(self):
        f = run_check("FROM ./model.gguf\n", "MODEL-003")
        assert f.severity == Severity.LOW

    def test_fails_on_local_gguf(self):
        f = run_check("FROM ./vicuna.Q4_0.gguf\n", "MODEL-003")
        assert not f.passed

    def test_flags_pickle_format(self):
        f = run_check("FROM /models/weights.bin\n", "MODEL-003")
        assert not f.passed
        assert "pickle" in f.description.lower()

    def test_passes_on_registry_ref(self):
        f = run_check("FROM llama3:8b\n", "MODEL-003")
        assert f.passed


class TestModel004RemoteAdapter:
    def test_fails_on_hub_adapter(self):
        f = run_check(
            "FROM llama3:8b\nADAPTER hf.co/someone/my-lora\n", "MODEL-004"
        )
        assert not f.passed

    def test_fails_on_registry_adapter(self):
        f = run_check("FROM llama3:8b\nADAPTER org/lora-pack\n", "MODEL-004")
        assert not f.passed

    def test_passes_on_local_adapter(self):
        f = run_check("FROM llama3:8b\nADAPTER ./local-lora.gguf\n", "MODEL-004")
        assert f.passed

    def test_passes_with_no_adapter(self):
        f = run_check("FROM llama3:8b\n", "MODEL-004")
        assert f.passed
