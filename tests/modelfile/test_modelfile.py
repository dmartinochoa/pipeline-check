"""Tests for the Modelfile provider (MODEL-001..006) and its parser."""
from __future__ import annotations

from pathlib import Path

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.modelfile.base import (
    ModelfileContext,
    WeightBlob,
    is_hf_model_config,
    parse_modelfile,
    ref_is_hub,
    ref_is_local,
    unsafe_weight_ext,
)
from pipeline_check.core.checks.modelfile.checks import ModelfileChecks

from .conftest import run_check, run_config_check


def _model006(ctx: ModelfileContext):
    for f in ModelfileChecks(ctx).run():
        if f.check_id == "MODEL-006":
            return f
    raise AssertionError("MODEL-006 not found")


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

    def test_fails_on_trailing_colon_empty_tag(self):
        # ``llama3:`` (trailing colon, no tag) resolves to the registry
        # default, just as unpinned as a bare name (Part-C FN: the empty
        # tag string was treated as pinned).
        f = run_check("FROM llama3:\n", "MODEL-001")
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


class TestHFConfigDetection:
    def test_is_hf_model_config_recognizes_markers(self):
        assert is_hf_model_config({"model_type": "llama"})
        assert is_hf_model_config({"architectures": ["X"]})
        assert is_hf_model_config({"auto_map": {}})

    def test_is_hf_model_config_rejects_unrelated(self):
        assert not is_hf_model_config({"compilerOptions": {}})
        assert not is_hf_model_config("not a dict")


class TestModel005ConfigCustomCode:
    def test_metadata(self):
        f = run_config_check({"model_type": "llama"}, "MODEL-005")
        assert f.check_id == "MODEL-005"
        assert f.severity is Severity.MEDIUM

    def test_fires_on_auto_map(self):
        f = run_config_check(
            {
                "model_type": "custom",
                "auto_map": {
                    "AutoConfig": "configuration_custom.CustomConfig",
                    "AutoModelForCausalLM": "modeling_custom.CustomModel",
                },
            },
            "MODEL-005",
        )
        assert not f.passed
        assert "modeling_custom.CustomModel" in f.description

    def test_fires_on_list_valued_auto_map(self):
        f = run_config_check(
            {"architectures": ["X"], "auto_map": {"AutoModel": ["a.B", "c.D"]}},
            "MODEL-005",
        )
        assert not f.passed

    def test_passes_on_standard_config(self):
        # A normal model config with no auto_map ships no custom code.
        f = run_config_check(
            {"model_type": "llama", "architectures": ["LlamaForCausalLM"]},
            "MODEL-005",
        )
        assert f.passed

    def test_passes_on_empty_auto_map(self):
        f = run_config_check(
            {"model_type": "llama", "auto_map": {}}, "MODEL-005"
        )
        assert f.passed


class TestHubRefWithWeightsExtension:
    """Regression: ``FROM hf.co/org/model.gguf`` is a remote hub pull, not a
    local weights file. The weights-extension classifier used to win over the
    hub classifier, suppressing MODEL-001 (false negative) and false-firing
    MODEL-003 on a documented Ollama syntax."""

    REF = "hf.co/TheBloke/Llama-2-7B-GGUF/model.gguf"

    def test_ref_is_not_local(self):
        assert ref_is_hub(self.REF) is True
        assert ref_is_local(self.REF) is False

    def test_model001_fires_unpinned(self):
        # An unpinned (no tag / digest) remote hub pull must be flagged.
        f = run_check(f"FROM {self.REF}\n", "MODEL-001")
        assert not f.passed

    def test_model002_fires_third_party_hub(self):
        f = run_check(f"FROM {self.REF}\n", "MODEL-002")
        assert not f.passed

    def test_model003_does_not_false_fire(self):
        # It is a remote pull, so the local-weights-blob rule must pass.
        f = run_check(f"FROM {self.REF}\n", "MODEL-003")
        assert f.passed

    def test_genuine_local_weights_still_local(self):
        assert ref_is_local("./model.gguf") is True
        assert ref_is_local("model.gguf") is True
        assert ref_is_local("/models/weights.bin") is True


class TestUnsafeWeightExt:
    """The MODEL-006 extension classifier (Tier-1 vs Tier-2)."""

    def test_tier1_fires_on_extension_alone(self):
        for name in (
            "a.pkl", "a.pickle", "a.pt", "a.pth", "a.ckpt",
            "a.joblib", "a.dill", "a.keras",
        ):
            assert unsafe_weight_ext(name, in_model_dir=False) is not None, name

    def test_safe_formats_never_fire(self):
        for name in ("a.safetensors", "a.gguf", "a.onnx"):
            assert unsafe_weight_ext(name, in_model_dir=True) is None, name

    def test_tier2_needs_model_context(self):
        # A bare data/firmware blob is not flagged...
        assert unsafe_weight_ext("firmware.bin", in_model_dir=False) is None
        assert unsafe_weight_ext("dataset.h5", in_model_dir=False) is None
        # ...but a model-ish name or a model directory qualifies it.
        assert unsafe_weight_ext("pytorch_model.bin", in_model_dir=False) == ".bin"
        assert unsafe_weight_ext("firmware.bin", in_model_dir=True) == ".bin"
        assert unsafe_weight_ext("model.h5", in_model_dir=False) == ".h5"

    def test_no_extension(self):
        assert unsafe_weight_ext("Modelfile", in_model_dir=True) is None


class TestMODEL006:
    """Committed model weights in a code-executing serialization format."""

    def test_passes_with_no_weight_blobs(self):
        f = _model006(ModelfileContext([], []))
        assert f.passed
        assert f.severity is Severity.LOW

    def test_fires_and_aggregates(self):
        ctx = ModelfileContext(
            [], [],
            weight_blobs=[
                WeightBlob(path="a.pkl", ext=".pkl"),
                WeightBlob(path="sub/b.pt", ext=".pt"),
            ],
            root=".",
        )
        f = _model006(ctx)
        assert not f.passed
        assert f.severity is Severity.LOW
        assert "2 committed model artifact(s)" in f.description
        assert {loc.path for loc in f.locations} == {"a.pkl", "sub/b.pt"}

    def test_from_path_tier_matrix(self, tmp_path):
        (tmp_path / "models").mkdir()
        (tmp_path / "hfmodel").mkdir()
        (tmp_path / "data").mkdir()
        # flagged
        (tmp_path / "preprocess.pkl").write_bytes(b"")
        (tmp_path / "sd.ckpt").write_bytes(b"")
        (tmp_path / "pytorch_model.bin").write_bytes(b"")
        (tmp_path / "hfmodel" / "weights.bin").write_bytes(b"")
        (tmp_path / "hfmodel" / "config.json").write_text(
            '{"model_type": "llama", "architectures": ["X"]}', encoding="utf-8",
        )
        # not flagged
        (tmp_path / "models" / "model.safetensors").write_bytes(b"")
        (tmp_path / "data" / "firmware.bin").write_bytes(b"")

        ctx = ModelfileContext.from_path(tmp_path)
        flagged = {Path(b.path).name for b in ctx.weight_blobs}
        assert flagged == {
            "preprocess.pkl", "sd.ckpt", "pytorch_model.bin", "weights.bin",
        }
        assert "firmware.bin" not in flagged
        assert "model.safetensors" not in flagged
        assert not _model006(ctx).passed

    def test_skips_vendored_dirs(self, tmp_path):
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "thing.pkl").write_bytes(b"")
        ctx = ModelfileContext.from_path(tmp_path)
        assert not ctx.weight_blobs
        assert _model006(ctx).passed
