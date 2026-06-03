"""Tests for phase-2 dataflow reachability (chains/_reachability.py)."""
from __future__ import annotations

import json
import textwrap

import yaml
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import chains
from pipeline_check.core.chains._reachability import assess_reachability
from pipeline_check.core.checks.argo.base import ArgoContext, ArgoDoc
from pipeline_check.core.checks.argo.pipelines import ArgoChecks
from pipeline_check.core.checks.base import Finding, Severity, TaintFlow
from pipeline_check.core.checks.buildkite.base import BuildkiteContext
from pipeline_check.core.checks.buildkite.base import Pipeline as BuildkitePipeline
from pipeline_check.core.checks.buildkite.pipelines import BuildkitePipelineChecks
from pipeline_check.core.checks.github.base import GitHubContext, Workflow
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext, Pipeline
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.tekton.base import TektonContext, TektonDoc
from pipeline_check.core.checks.tekton.pipelines import TektonChecks

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


class TestAC022GitLabDataflow:
    """GitLab AC-022 confirms reachability via the dotenv taint graph."""

    _GL_DATAFLOW = textwrap.dedent("""
        stages: [build, deploy]
        extract:
          stage: build
          script:
            - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
          artifacts:
            reports:
              dotenv: taint.env
        deploy:
          stage: deploy
          needs: [extract]
          script:
            - ./deploy.sh $TITLE
    """)

    def _evaluate(self, gl_text: str) -> list:
        ctx = GitLabContext(
            [Pipeline(path=".gitlab-ci.yml", data=yaml.safe_load(gl_text))]
        )
        findings = GitLabPipelineChecks(ctx).run()
        return findings, [
            c for c in chains.engine.evaluate(findings) if c.chain_id == "AC-022"
        ]

    def test_dotenv_dataflow_confirmed(self):
        findings, ac = self._evaluate(self._GL_DATAFLOW)
        assert ac, "AC-022 should fire"
        c = ac[0]
        assert c.confirmed_reachable
        assert c.via_dataflow
        assert "taint path" in c.reachability_note

    def test_taint004_exposes_structured_flow(self):
        findings, _ = self._evaluate(self._GL_DATAFLOW)
        taint = [
            f for f in findings
            if f.check_id == "TAINT-004" and not f.passed
        ]
        assert taint
        assert any(
            fl.source_job == "extract" and fl.sink_job == "deploy"
            for fl in taint[0].taint_flows
        )


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


# ── AC-026 Buildkite (meta-data taint graph) ────────────────────────────


class TestAC026BuildkiteDataflow:
    """AC-026 confirms reachability via the Buildkite meta-data taint
    graph. The producer step quotes the untrusted value (so it's safe in
    its own shell) but still writes it to meta-data; the ungated deploy
    step reads it back, the cross-step path BK-003's single-step check
    can't see on its own."""

    _BK_DATAFLOW = textwrap.dedent("""
        steps:
          - label: extract
            command: |
              echo building $BUILDKITE_BRANCH
              buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST_TITLE"
          - wait
          - label: deploy
            command: |
              TITLE=$(buildkite-agent meta-data get title)
              ./deploy.sh $TITLE
    """)

    def _evaluate(self, text: str):
        ctx = BuildkiteContext(
            [BuildkitePipeline(path=".buildkite/pipeline.yml",
                               data=yaml.safe_load(text))]
        )
        findings = BuildkitePipelineChecks(ctx).run()
        return findings, [
            c for c in chains.engine.evaluate(findings) if c.chain_id == "AC-026"
        ]

    def test_metadata_dataflow_confirmed(self):
        _findings, ac = self._evaluate(self._BK_DATAFLOW)
        assert ac, "AC-026 should fire"
        c = ac[0]
        assert c.confirmed_reachable
        assert c.via_dataflow
        assert "taint path" in c.reachability_note

    def test_taint005_exposes_structured_flow(self):
        findings, _ = self._evaluate(self._BK_DATAFLOW)
        taint = [
            f for f in findings
            if f.check_id == "TAINT-005" and not f.passed
        ]
        assert taint
        assert any(
            fl.source_job == "extract" and fl.sink_job == "deploy"
            for fl in taint[0].taint_flows
        )


# ── AC-025 Argo (outputs.parameters taint graph) ────────────────────────


class TestAC025ArgoDataflow:
    """AC-025 confirms reachability via the Argo outputs.parameters taint
    graph: a producer template's tainted output is forwarded into a
    *separate* privileged template, so the injection reaches the
    kernel-privileged container across templates."""

    _ARGO_DATAFLOW = textwrap.dedent("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: { name: build }
        spec:
          entrypoint: main
          arguments: { parameters: [ { name: title } ] }
          templates:
            - name: main
              dag:
                tasks:
                  - name: produce
                    template: read-title
                    arguments:
                      parameters:
                        - { name: title, value: "{{workflow.parameters.title}}" }
                  - name: consume
                    template: ship
                    dependencies: [produce]
                    arguments:
                      parameters:
                        - name: clean_title
                          value: "{{tasks.produce.outputs.parameters.title}}"
            - name: read-title
              inputs: { parameters: [ { name: title } ] }
              outputs:
                parameters:
                  - { name: title, valueFrom: { path: /tmp/t } }
              script:
                image: alpine@sha256:abc
                command: [sh]
                source: |
                  echo {{inputs.parameters.title}} > /tmp/t
            - name: ship
              inputs: { parameters: [ { name: clean_title } ] }
              script:
                image: alpine@sha256:abc
                securityContext: { privileged: true }
                command: [sh]
                source: |
                  echo "{{inputs.parameters.clean_title}}"
    """)

    def _evaluate(self, text: str):
        data = yaml.safe_load(text)
        doc = ArgoDoc(
            path="argo/build.yaml", doc_index=0,
            api_version=str(data.get("apiVersion", "")),
            kind=str(data.get("kind", "")),
            name=str((data.get("metadata") or {}).get("name", "")),
            namespace="", data=data,
        )
        findings = ArgoChecks(ArgoContext([doc])).run()
        return findings, [
            c for c in chains.engine.evaluate(findings) if c.chain_id == "AC-025"
        ]

    def test_outputs_dataflow_confirmed(self):
        _findings, ac = self._evaluate(self._ARGO_DATAFLOW)
        assert ac, "AC-025 should fire"
        c = ac[0]
        assert c.confirmed_reachable
        assert c.via_dataflow
        assert "taint path" in c.reachability_note

    def test_taint007_exposes_structured_flow(self):
        findings, _ = self._evaluate(self._ARGO_DATAFLOW)
        taint = [
            f for f in findings
            if f.check_id == "TAINT-007" and not f.passed
        ]
        assert taint
        # Flows are qualified with the document's <Kind>/<name>: prefix so
        # they line up with ARGO-002 / ARGO-005's template anchors.
        assert any(
            fl.source_job == "Workflow/build:read-title"
            and fl.sink_job == "Workflow/build:ship"
            for fl in taint[0].taint_flows
        )


# ── AC-023 Tekton (results taint graph, cross-document) ──────────────────


class TestAC023TektonDataflow:
    """AC-023 confirms reachability via the Tekton results taint graph.
    TKN-003 fires only in ``extract-task`` and TKN-002 only in
    ``build-task`` (different Tasks, so the step-level shared check can't
    fire), but TAINT-006 bridges them: the tainted result flows from the
    extract Task into the privileged build Task via ``taskRef``."""

    def _docs(self):
        def mk(text: str) -> TektonDoc:
            d = yaml.safe_load(text)
            return TektonDoc(
                path="tekton/x.yaml", doc_index=0,
                api_version=str(d.get("apiVersion", "")),
                kind=str(d.get("kind", "")),
                name=str((d.get("metadata") or {}).get("name", "")),
                namespace="", data=d,
            )
        pipeline = mk(textwrap.dedent("""
            apiVersion: tekton.dev/v1
            kind: Pipeline
            metadata: { name: p }
            spec:
              tasks:
                - name: extract
                  taskRef: { name: extract-task }
                  params: [ { name: title, value: $(params.pr-title) } ]
                - name: build
                  runAfter: [extract]
                  taskRef: { name: build-task }
                  params: [ { name: clean, value: $(tasks.extract.results.clean) } ]
        """))
        extract = mk(textwrap.dedent("""
            apiVersion: tekton.dev/v1
            kind: Task
            metadata: { name: extract-task }
            spec:
              params: [ { name: title } ]
              results: [ { name: clean } ]
              steps:
                - name: extract
                  image: alpine@sha256:abc
                  securityContext:
                    privileged: false
                    runAsNonRoot: true
                    runAsUser: 10001
                  script: |
                    echo $(params.title) > $(results.clean.path)
        """))
        build = mk(textwrap.dedent("""
            apiVersion: tekton.dev/v1
            kind: Task
            metadata: { name: build-task }
            spec:
              params: [ { name: clean } ]
              steps:
                - name: build
                  image: alpine@sha256:abc
                  securityContext: { privileged: true }
                  script: |
                    echo "$(params.clean)"
        """))
        return [pipeline, extract, build]

    def _evaluate(self):
        findings = TektonChecks(TektonContext(self._docs())).run()
        return findings, [
            c for c in chains.engine.evaluate(findings) if c.chain_id == "AC-023"
        ]

    def test_results_dataflow_confirmed(self):
        _findings, ac = self._evaluate()
        assert ac, "AC-023 should fire"
        c = ac[0]
        assert c.confirmed_reachable
        assert c.via_dataflow
        assert "taint path" in c.reachability_note

    def test_taint006_exposes_structured_flow(self):
        findings, _ = self._evaluate()
        taint = [
            f for f in findings
            if f.check_id == "TAINT-006" and not f.passed
        ]
        assert taint
        # taskRef tasks resolve to their backing <Kind>/<name> document id
        # so the flow lines up with TKN-002 / TKN-003's anchor prefix.
        assert any(
            fl.source_job == "Task/extract-task"
            and fl.sink_job == "Task/build-task"
            for fl in taint[0].taint_flows
        )
