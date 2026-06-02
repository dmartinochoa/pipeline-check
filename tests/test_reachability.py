"""Tests for phase-2 dataflow reachability (chains/_reachability.py)."""
from __future__ import annotations

import json
import textwrap

import yaml
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import chains
from pipeline_check.core.chains._reachability import assess_reachability
from pipeline_check.core.checks.base import Finding, Severity, TaintFlow
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks

_DATAFLOW_WF = """\
name: ci
on: issues
jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.x.outputs.title }}
    steps:
      - id: x
        run: echo "title=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
  deploy:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh --title ${{ needs.extract.outputs.title }}
"""

_COOCCUR_WF = """\
name: ci
on: issues
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
"""


def _taint_finding(*flows: TaintFlow) -> Finding:
    return Finding(
        check_id="TAINT-002", title="t", severity=Severity.HIGH,
        resource="wf.yml", description="", recommendation="", passed=False,
        taint_flows=tuple(flows),
    )


def _flow(src: str, sink: str) -> TaintFlow:
    return TaintFlow(source_job=src, sink_job=sink, rendered=f"{src}->{sink}")


# ── assess_reachability unit tests ──────────────────────────────────────


class TestAssessReachability:
    def test_direct_dataflow_edge(self):
        tf = _taint_finding(_flow("extract", "deploy"))
        r = assess_reachability([tf], {"extract"}, {"deploy"})
        assert r.confirmed and r.via_dataflow
        assert "extract" in r.note and "deploy" in r.note
        assert r.path == "extract->deploy"

    def test_self_edge_same_job(self):
        # A single-job producer/consumer flow: source_job == sink_job.
        tf = _taint_finding(_flow("build", "build"))
        r = assess_reachability([tf], {"build"}, {"build"})
        assert r.confirmed and r.via_dataflow

    def test_multi_hop_chain(self):
        # extract -> middle -> deploy via two separate flows.
        tf = _taint_finding(_flow("extract", "middle"), _flow("middle", "deploy"))
        r = assess_reachability([tf], {"extract"}, {"deploy"})
        assert r.confirmed and r.via_dataflow

    def test_shared_job_fallback_when_no_flow(self):
        # No taint flow connects them, but the legs share a job.
        r = assess_reachability([], {"build"}, {"build"})
        assert r.confirmed and not r.via_dataflow
        assert "share job" in r.note

    def test_unconfirmed_when_disjoint_and_no_flow(self):
        r = assess_reachability([], {"a"}, {"b"})
        assert not r.confirmed and not r.via_dataflow

    def test_dataflow_preferred_over_shared(self):
        # Both a dataflow path AND a shared job exist; dataflow wins.
        tf = _taint_finding(_flow("a", "b"))
        r = assess_reachability([tf], {"a", "b"}, {"b"})
        assert r.via_dataflow

    def test_flow_to_wrong_sink_not_confirmed(self):
        tf = _taint_finding(_flow("a", "c"))
        r = assess_reachability([tf], {"a"}, {"b"})
        assert not r.confirmed


# ── AC-002 end-to-end (real workflow -> chain) ──────────────────────────


def _evaluate(wf_text: str) -> list:
    ctx = GitHubContext(
        [Workflow(path=".github/workflows/ci.yml", data=yaml.safe_load(wf_text))]
    )
    findings = WorkflowChecks(ctx).run()
    return [c for c in chains.engine.evaluate(findings) if c.chain_id == "AC-002"]


class TestAC002Dataflow:
    def test_cross_job_dataflow_confirmed(self):
        wf = textwrap.dedent("""
            name: ci
            on: issues
            jobs:
              extract:
                runs-on: ubuntu-latest
                outputs:
                  title: ${{ steps.x.outputs.title }}
                steps:
                  - id: x
                    run: echo "title=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
              deploy:
                needs: extract
                runs-on: ubuntu-latest
                steps:
                  - run: ./deploy.sh --title ${{ needs.extract.outputs.title }}
        """)
        ac = _evaluate(wf)
        assert ac, "AC-002 should fire"
        c = ac[0]
        assert c.confirmed_reachable
        assert c.via_dataflow
        assert "taint path" in c.reachability_note
        assert c.to_dict().get("via_dataflow") is True

    def test_taint_finding_exposes_structured_flow(self):
        wf = textwrap.dedent("""
            name: ci
            on: issues
            jobs:
              extract:
                runs-on: ubuntu-latest
                outputs:
                  title: ${{ steps.x.outputs.title }}
                steps:
                  - id: x
                    run: echo "title=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
              deploy:
                needs: extract
                runs-on: ubuntu-latest
                steps:
                  - run: ./deploy.sh --title ${{ needs.extract.outputs.title }}
        """)
        ctx = GitHubContext(
            [Workflow(path="wf.yml", data=yaml.safe_load(wf))]
        )
        findings = WorkflowChecks(ctx).run()
        taint = [
            f for f in findings
            if f.check_id == "TAINT-002" and not f.passed
        ]
        assert taint
        flows = taint[0].taint_flows
        assert any(
            fl.source_job == "extract" and fl.sink_job == "deploy"
            for fl in flows
        )

    def test_same_workflow_disjoint_jobs_not_dataflow(self):
        # Injection in one job, an unrelated ungated deploy in another,
        # with no taint flow between them: chain still fires (co-occur)
        # but is not via_dataflow and not shared-job-confirmed.
        wf = textwrap.dedent("""
            name: ci
            on: issues
            jobs:
              probe:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.issue.title }}"
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - run: ./deploy.sh
        """)
        ac = _evaluate(wf)
        assert ac, "AC-002 should still fire on co-occurrence"
        c = ac[0]
        assert not c.via_dataflow
        assert not c.confirmed_reachable


class TestChainsRequireDataflowFlag:
    """``--chains-require-dataflow`` keeps only dataflow-confirmed chains."""

    def _run(self, tmp_path, monkeypatch, wf_text, *extra):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(wf_text)
        monkeypatch.chdir(tmp_path)
        return CliRunner().invoke(
            scan,
            ["--pipeline", "github", "--output", "json", *extra],
        )

    def _chain_ids(self, result):
        return {
            c["chain_id"] for c in json.loads(result.stdout).get("chains", [])
        }

    def test_dataflow_chain_survives_flag(self, tmp_path, monkeypatch):
        result = self._run(
            tmp_path, monkeypatch, _DATAFLOW_WF, "--chains-require-dataflow",
        )
        assert "AC-002" in self._chain_ids(result)

    def test_cooccurrence_chain_dropped_by_flag(self, tmp_path, monkeypatch):
        # Without the flag AC-002 is present; with it, the co-occurrence
        # instance (no dataflow path) is filtered out.
        plain = self._run(tmp_path, monkeypatch, _COOCCUR_WF)
        assert "AC-002" in self._chain_ids(plain)

    def test_cooccurrence_chain_dropped_with_flag(self, tmp_path, monkeypatch):
        result = self._run(
            tmp_path, monkeypatch, _COOCCUR_WF, "--chains-require-dataflow",
        )
        assert "AC-002" not in self._chain_ids(result)
