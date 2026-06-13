"""Tests for the local-LLM triage core (transport / parsing / snippet).

No real network calls are made; the HTTP transport is mocked.
"""
from __future__ import annotations

import json
import urllib.error
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.triage import (
    DEFAULT_ENDPOINT,
    TriageLabel,
    TriageVerdict,
    extract_snippet,
    is_local_endpoint,
    parse_model_reply,
    triage_finding,
    triage_findings,
)
from pipeline_check.core.triage_prompts import build_prompt


def _f(check_id="GHA-002", severity=Severity.HIGH, **kw):
    return Finding(
        check_id=check_id,
        title=kw.get("title", "Script injection"),
        severity=severity,
        resource=kw.get("resource", ".github/workflows/ci.yml"),
        description=kw.get("description", "Untrusted input in run."),
        recommendation="Fix it.",
        passed=False,
        locations=kw.get("locations", []),
    )


@contextmanager
def _mock_urlopen(*, response_text=None, body=None, exc=None):
    """Patch triage.urllib.request.urlopen to return a canned Ollama
    response, or to raise *exc*."""
    target = "pipeline_check.core.triage.urllib.request.urlopen"
    if exc is not None:
        with patch(target, side_effect=exc) as m:
            yield m
        return
    if body is None:
        body = json.dumps({"response": response_text}).encode()
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = body
    cm.__exit__.return_value = False
    with patch(target, return_value=cm) as m:
        yield m


class TestIsLocalEndpoint:
    def test_loopback_hosts_are_local(self):
        assert is_local_endpoint(DEFAULT_ENDPOINT)
        assert is_local_endpoint("http://127.0.0.1:8080/api/generate")
        assert is_local_endpoint("http://localhost:1234/v1")

    def test_remote_hosts_are_not_local(self):
        assert not is_local_endpoint("https://api.openai.com/v1/chat")
        assert not is_local_endpoint("http://10.0.0.5:11434/api/generate")

    def test_garbage_endpoint_is_not_local(self):
        assert not is_local_endpoint("not a url")
        assert not is_local_endpoint("")


class TestParseModelReply:
    def test_clean_json(self):
        v = parse_model_reply('{"label": "confirmed", "rationale": "reachable"}')
        assert v.label is TriageLabel.CONFIRMED
        assert v.rationale == "reachable"

    def test_label_aliases_normalize(self):
        assert parse_model_reply('{"label":"false_positive"}').label is TriageLabel.LIKELY_FP
        assert parse_model_reply('{"verdict":"exploitable"}').label is TriageLabel.CONFIRMED
        assert parse_model_reply('{"label":"UNSURE"}').label is TriageLabel.NEEDS_REVIEW

    def test_json_embedded_in_prose(self):
        reply = 'Sure! Here is my verdict:\n{"label": "likely_fp", "reason": "guarded"}\nHope that helps.'
        v = parse_model_reply(reply)
        assert v.label is TriageLabel.LIKELY_FP
        assert v.rationale == "guarded"

    def test_mention_only_fallback(self):
        v = parse_model_reply("I think this is a likely_fp given the env block.")
        assert v.label is TriageLabel.LIKELY_FP

    def test_unrecognized_reply_is_unavailable(self):
        v = parse_model_reply("the weather is nice today")
        assert v.label is TriageLabel.UNAVAILABLE

    def test_json_without_label_is_unavailable(self):
        assert parse_model_reply('{"foo": "bar"}').label is TriageLabel.UNAVAILABLE

    def test_non_dict_json_without_a_label_is_unavailable(self):
        # A JSON array (not an object) with no label mention falls through
        # to UNAVAILABLE; the lenient mention fallback would still catch a
        # bare label substring, which is intended.
        assert parse_model_reply("[1, 2, 3]").label is TriageLabel.UNAVAILABLE


class TestTriageFinding:
    def test_verified_reply(self):
        with _mock_urlopen(response_text='{"label":"confirmed","rationale":"PR title reaches run"}'):
            v = triage_finding(_f(), "snippet")
        assert v.label is TriageLabel.CONFIRMED
        assert "PR title" in v.rationale

    def test_endpoint_unreachable_is_unavailable(self):
        with _mock_urlopen(exc=urllib.error.URLError("connection refused")):
            v = triage_finding(_f(), "snippet")
        assert v.label is TriageLabel.UNAVAILABLE

    def test_timeout_is_unavailable(self):
        with _mock_urlopen(exc=TimeoutError("timed out")):
            v = triage_finding(_f(), "snippet")
        assert v.label is TriageLabel.UNAVAILABLE

    def test_backend_returns_object_directly(self):
        # A non-Ollama backend that returns the label object as the whole body.
        body = json.dumps({"label": "needs_review"}).encode()
        with _mock_urlopen(body=body):
            v = triage_finding(_f(), "snippet")
        assert v.label is TriageLabel.NEEDS_REVIEW

    def test_posts_to_the_given_endpoint(self):
        with _mock_urlopen(response_text='{"label":"confirmed"}') as m:
            triage_finding(_f(), "s", endpoint="http://localhost:9/api/generate", model="m")
        req = m.call_args[0][0]
        assert req.full_url == "http://localhost:9/api/generate"
        sent = json.loads(req.data)
        assert sent["model"] == "m" and sent["stream"] is False


class TestExtractSnippet:
    def test_marks_the_offending_line(self, tmp_path):
        p = tmp_path / "ci.yml"
        p.write_text("\n".join(f"line{i}" for i in range(1, 11)), encoding="utf-8")
        f = _f(locations=[Location(path=str(p), start_line=5)])
        snip = extract_snippet(f, context=2)
        assert ">    5 | line5" in snip
        assert "  3 | line3" in snip and "  7 | line7" in snip
        assert "line2" not in snip  # outside the +-2 window

    def test_no_location_returns_empty(self):
        assert extract_snippet(_f(locations=[])) == ""

    def test_unreadable_file_returns_empty(self):
        f = _f(locations=[Location(path="/no/such/file.yml", start_line=1)])
        assert extract_snippet(f) == ""


class TestTriageFindings:
    def test_preserves_order_and_pairs_verdicts(self):
        findings = [_f(check_id="A"), _f(check_id="B")]
        with patch(
            "pipeline_check.core.triage.triage_finding",
            side_effect=[
                TriageVerdict(TriageLabel.CONFIRMED),
                TriageVerdict(TriageLabel.LIKELY_FP),
            ],
        ):
            out = triage_findings(findings)
        assert [f.check_id for f, _ in out] == ["A", "B"]
        assert [v.label for _, v in out] == [TriageLabel.CONFIRMED, TriageLabel.LIKELY_FP]


class TestBuildPrompt:
    def test_includes_finding_and_snippet_and_asks_for_json(self):
        prompt = build_prompt(_f(check_id="GHA-002"), "  > 6 | run: echo ${{ ... }}")
        assert "GHA-002" in prompt
        assert "Script injection" in prompt
        assert "run: echo" in prompt
        assert '"label"' in prompt and "likely_fp" in prompt

    def test_empty_snippet_is_noted(self):
        prompt = build_prompt(_f(), "")
        assert "(no source snippet available)" in prompt
