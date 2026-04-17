"""Long-form CLI manual — the content behind ``--man``.

``--help`` is the one-line-per-flag reference; this module is the
narrative that ``--help`` deliberately omits. Each topic is a
self-contained chunk of plain text suitable for a terminal: no rich
markup, no ANSI colours, no required width. Pipe to ``less`` or
``cat`` and it reads the same.

Topic content is owned here rather than in the CLI module so it can
be unit-tested without invoking click — and so adding a topic is a
one-dictionary-entry change.
"""
from __future__ import annotations

# Topic body strings end with a single trailing newline; the renderer
# adds a blank line between topic header and body and between body
# and footer.

INDEX = """\
pipeline_check is a CI/CD security posture scanner. ``--help`` lists
every flag in one place; ``--man [TOPIC]`` is the narrative version
with end-to-end examples and the reasoning behind each subsystem.

Available topics:

  gate        How the CI gate decides pass / fail and what the
              --fail-on / --min-grade / --max-failures / --baseline /
              --ignore-file flags do.
  autofix     --fix and --fix --apply: what each registered fixer
              does, how they compose, and how to write your own.
  diff        --diff-base for scoping a scan to changed files only.
              Terraform / workflow / AWS provider semantics.
  secrets     --secret-pattern for org-specific token shapes; what the
              built-in detectors catch.
  standards   --standard / --list-standards / --standard-report. How
              compliance enrichment works and how to add a standard.
  config      .pipeline-check.yml / pyproject.toml / env vars +
              --config-check.
  output      --output formats, where each lands, exit codes.
  inventory   --inventory / --inventory-type / --inventory-only:
              surfacing the list of components the scanner discovered,
              per-provider component types, and asset-register use.
  lambda      Running pipeline_check as an AWS Lambda — payload
              shapes, fan-out, IAM, return value.
  recipes     End-to-end command examples for the most common
              workflows (PR gate, nightly drift, baseline rollout,
              inventory export).
  explain     ``--explain CHECK_ID`` — per-check reference: severity,
              confidence, compliance mappings, docs note, known FP
              modes, and the recommended fix.

Run e.g. ``pipeline_check --man gate`` for any topic above.
"""


GATE = """\
TOPIC: gate

The CI gate turns a scan result into a single pass / fail decision.
It has FOUR fail conditions and TWO subtractive filters; any tripped
condition fails the gate (logical OR), and filters always run before
conditions are evaluated.

Fail conditions
---------------
--fail-on SEV
    Fail when ANY effective finding's severity is >= SEV. SEV is one
    of CRITICAL / HIGH / MEDIUM / LOW / INFO.

--min-grade A|B|C|D
    Fail when the overall grade is worse than the bar. A is best.

--max-failures N
    Fail when more than N effective failing findings are present.

--fail-on-check ID
    Fail when a named check is in the effective set. Repeat for many.
    Useful for "we tolerate everything except this one regression."

Default gate
------------
When no explicit condition is set, the gate behaves as if you had
passed ``--fail-on CRITICAL``. The implicit default applies after
baseline + ignore filtering, so a CRITICAL already in the baseline or
ignored does NOT trip it. Set any explicit condition to suppress the
default.

Subtractive filters
-------------------
--baseline PATH
    Drop every current finding that already failed in a prior JSON
    report. Use this on adoption: capture today's state once, then
    only block on regressions.

--baseline-from-git REF:PATH
    Same idea but resolves the baseline via ``git show REF:PATH``,
    so you don't need to carry the JSON as a CI artifact.

--ignore-file PATH
    Drop hand-curated suppressions. Two formats:
      Flat (default ``.pipelinecheckignore``):
          CHECK_ID                 # suppress everywhere
          CHECK_ID:RESOURCE        # suppress for one resource
      YAML (``.yml`` / ``.yaml`` extension):
          - check_id: GHA-001
            resource: .github/workflows/release.yml
            expires: 2026-06-30
            reason: waiting on Dependabot
    Expired YAML rules no longer suppress and surface in the gate
    summary as warnings — debt that doesn't rot silently.

Exit codes
----------
0  Gate passed.
1  Gate failed (one of the conditions above tripped).
2  Scanner error (stack trace printed to stderr).
3  --config-check found unknown keys.

Recipes
-------
# Block CRITICAL only (lenient rollout)
pipeline_check --pipeline aws --fail-on CRITICAL

# B-or-better grade
pipeline_check --pipeline aws --min-grade B

# Only block on NEW regressions
pipeline_check --pipeline aws --output json > baseline.json   # once
pipeline_check --pipeline aws --baseline baseline.json --fail-on HIGH
"""


AUTOFIX = """\
TOPIC: autofix

For a subset of checks, pipeline_check can emit the exact source edit
that would remediate the finding. The output is a standard unified
diff so it composes with ``git apply``.

--fix
    Print one diff per failing finding that has a registered fixer.
    Stdout by default; stderr when --output is json/sarif/html/both
    so the machine-readable stream stays valid. File reads are
    cached, so multiple findings against the same file don't re-read
    it. Per-fixer exceptions log to stderr and are skipped — one
    broken fixer never aborts the run.

--fix --apply
    Write the patches in place instead of printing them. Reports
    "N file(s) modified" to stderr. Opt-in (dry-run by default)
    and only valid alongside --fix.

Registered fixers
-----------------
GHA-002  Adds ``persist-credentials: false`` under every
         actions/checkout step. Recognises both single-line
         (``- uses: actions/checkout@v4``) and named-step
         (``- name: ... / uses: ...``) forms. Idempotent.

GHA-004  Inserts ``permissions: contents: read`` at the top of
         the workflow. Idempotent — skips files that already
         declare any top-level permissions block.

GHA-008  Replaces credential-shaped literals with ``"<REDACTED>"``
         and a ``# TODO(pipelineguard): rotate ...`` marker.
         Preserves any operator comment on the line so existing
         context (ticket numbers, blame hints) survives.

Why not more
------------
GHA-001 (SHA-pin actions) requires a network call to the GitHub
API to resolve a tag to a commit SHA — out of scope for an
offline scanner. Use Dependabot or StepSecurity's
``pin-github-action`` for that one.

Workflow examples
-----------------
# Stream patch to git apply
pipeline_check --pipeline github --fix | git apply

# Apply directly, then diff to review
pipeline_check --pipeline github --fix --apply
git diff

# Run without applying so a reviewer sees what the bot WOULD do
pipeline_check --pipeline github --fix --output sarif --output-file r.sarif
# (the patch goes to stderr; the SARIF report goes to r.sarif)
"""


DIFF = """\
TOPIC: diff

--diff-base REF
    Scope the scan to files / resources changed since REF. Runs
    ``git diff --name-only REF...HEAD`` and intersects the result
    with the provider's loaded context. If git is unavailable or
    the ref doesn't resolve, the flag silently no-ops and a full
    scan runs (over-scanning is safer than silently skipping
    everything in CI).

Per-provider semantics
----------------------
github / gitlab / bitbucket / azure / jenkins
    Loads every workflow file as before, then drops the ones not
    touched by the diff. Common case for PR pipelines: only the
    files the PR actually changes get scanned.

terraform
    Loads the plan, then drops planned resources whose module
    directory wasn't touched by the diff. A change to
    ``modules/vpc/main.tf`` keeps ``module.vpc.*`` resources;
    ``main.tf`` at the repo root is treated as a "root module
    change" and keeps every root-level resource.

aws
    Rejected with a clear error. Live AWS resources aren't bound
    to git refs, so --diff-base has no natural analogue. Narrow
    the scope with ``--target NAME`` instead.

Examples
--------
# PR pipeline: only block on workflows the PR touches
pipeline_check --pipeline github --diff-base origin/main --fail-on HIGH

# Terraform: scan resources whose modules changed in this branch
pipeline_check --pipeline terraform --tf-plan plan.json \\
    --diff-base origin/main
"""


SECRETS = """\
TOPIC: secrets

Two layers of secret detection ship by default:

YAML-declared variable scans
----------------------------
GL-003 / BB-003 / ADO-003 read each provider's variable block
(``variables:`` for GitLab and Azure, ``definitions.variables``
for Bitbucket) and flag entries whose VARIABLE NAME matches the
"secretish" pattern (password / token / api_key / etc.) AND whose
value is a literal string.

Whole-document credential scans (-008)
--------------------------------------
GHA-008 / GL-008 / BB-008 / ADO-008 / JF-008 walk every string in
the document — script bodies, env values, embedded config — and
flag any token matching one of the built-in credential-shape
detectors. Each hit carries its detector name so operators can
group findings by secret type and write targeted ignore rules.

Built-in detector catalogue:

  aws_access_key        AKIA...... / ASIA......
  github_token          ghp_ / gho_ / ghu_ / ghs_ / ghr_
  slack_token           xoxa- / xoxb- / xoxp- / xoxr- / xoxs-
  jwt                   eyJ.....eyJ......sig
  stripe_secret         sk_live_ / sk_test_ / rk_live_ / rk_test_
  stripe_publishable    pk_live_ / pk_test_
  google_api_key        AIza<35 chars>
  npm_token             npm_<36 chars>
  pypi_token            pypi-AgEIcHlwaS5vcmc<...>
  docker_hub_pat        dckr_pat_<20+ chars>
  gitlab_pat            glpat-<20 chars>
  gitlab_deploy_token   gldt-<20+ chars>
  sendgrid              SG.<22>.<43>
  anthropic_api_key     sk-ant-api03-<90+ chars>
  digitalocean_token    dop_v1_<64 hex>
  hashicorp_vault       hvs.<24+ chars>
  twilio_api_key        SK<32 hex>
  twilio_account_sid    AC<32 hex>
  mailchimp_api_key     <32 hex>-us<1-2 digits>
  shopify_token         shpat_ / shpca_ / shppa_ / shpss_ + <32 hex>
  databricks_token      dapi<32 hex>
  openai_api_key        sk-<...>T3BlbkFJ<...> / sk-proj-<40+ chars>
  huggingface_token     hf_<34+ chars>
  age_secret_key        AGE-SECRET-KEY-1<58 chars>
  linear_api_key        lin_api_<40 chars>
  planetscale_token     pscale_tkn_<40+ chars>
  new_relic_api_key     NRAK-<27 chars>
  grafana_api_key       glsa_<32+ chars>
  telegram_bot_token    <8-10 digits>:<35 chars>
  private_key           multi-line PEM BEGIN markers (RSA/EC/OPENSSH/PGP)

Placeholder suppression
-----------------------
Tokens containing obvious doc markers (``<your-key>``, ``XXXXX``,
``replace_me``, ``dummy_key``, ``your_token``, ``my_secret``) are
suppressed before reaching the user — they're noise. The AWS
canonical example ``AKIAIOSFODNN7EXAMPLE`` is DELIBERATELY left
flagged: if it lands in a real workflow it almost always means
someone copy-pasted from docs and forgot to substitute.

Adding org-specific patterns
----------------------------
--secret-pattern REGEX (repeatable)
    Append a Python regex to the detector. Anchor with ^...$ for
    whole-token match. The token stream is split on whitespace
    and common shell separators before each pattern is tested.

Or in config (config.md):

    secret_patterns:
      - '^acme_[a-f0-9]{32}$'
      - '^xoxo-[A-Z0-9]{20,}$'

Examples
--------
# Internal token shape: acme_<32 hex>
pipeline_check --pipeline github \\
    --secret-pattern '^acme_[a-f0-9]{32}$'

# Run only the secret-scanning checks across every provider
pipeline_check --pipeline github --checks '*-008'
"""


STANDARDS = """\
TOPIC: standards

Every finding is enriched with a list of ControlRef objects —
references to controls in registered compliance standards. One
check can evidence controls in multiple standards at once, so a
single scan satisfies multiple frameworks.

Shipped standards
-----------------
owasp_cicd_top_10        OWASP Top 10 CI/CD Security Risks
cis_aws_foundations      CIS AWS Foundations Benchmark (subset)
cis_supply_chain         CIS Software Supply Chain Security Guide
nist_ssdf                NIST SP 800-218 v1.1
nist_800_53              NIST SP 800-53 Rev. 5 (CI/CD subset)
slsa                     SLSA Build Track v1.0
pci_dss_v4               PCI DSS v4.0 (CI/CD subset)
esf_supply_chain         NSA/CISA ESF Supply Chain

Flags
-----
--standard NAME (repeatable)
    Restrict ControlRef enrichment to the named standards. Without
    this flag, every registered standard contributes refs.

--list-standards
    Print every registered standard and exit.

--standard-report NAME
    Print the control -> check matrix for a standard, plus a
    "Gaps" section listing controls with no mapped check. Turns
    the tool into a coverage-audit explorer.

Adding a standard
-----------------
Create one Python module under
pipeline_check/core/standards/data/ that exports a STANDARD
object with .controls and .mappings dicts. Register it in
pipeline_check/core/standards/__init__.py. The CLI picks it up
automatically — no other code change needed.

Examples
--------
pipeline_check --list-standards
pipeline_check --standard-report nist_ssdf
pipeline_check --pipeline aws --standard owasp_cicd_top_10
"""


CONFIG = """\
TOPIC: config

Every CLI flag can be set in a config file so CI invocations stay
short and repo policy lives with the code.

File discovery
--------------
Without --config, the first match wins:

  1. .pipeline-check.yml / .pipeline-check.yaml at cwd
  2. pyproject.toml ([tool.pipeline_check] table) at cwd

--config PATH selects an explicit file; missing path raises
UsageError (no silent fallback).

Precedence
----------
Highest wins:

  1. CLI flags
  2. Environment variables (PIPELINE_CHECK_*, PIPELINE_CHECK_GATE_*)
  3. Config file
  4. Built-in defaults

Schema
------
Every CLI flag maps to a snake_case config key. Gate settings live
under a nested ``gate`` sub-section.

  pyproject.toml:
      [tool.pipeline_check]
      pipeline = "aws"
      standards = ["owasp_cicd_top_10"]

      [tool.pipeline_check.gate]
      fail_on = "HIGH"

  .pipeline-check.yml:
      pipeline: aws
      standards: [owasp_cicd_top_10]
      gate:
        fail_on: HIGH

Environment variables
---------------------
Upper-snake-case the option name and prefix with PIPELINE_CHECK_.
Gate options use PIPELINE_CHECK_GATE_. Multi-value options are
comma-separated.

  export PIPELINE_CHECK_PIPELINE=aws
  export PIPELINE_CHECK_GATE_FAIL_ON=HIGH
  export PIPELINE_CHECK_STANDARDS=owasp_cicd_top_10,nist_ssdf

Validation
----------
Unknown keys are ignored with a stderr warning. To fail CI on a
typo, run ``pipeline_check --config-check`` as a separate step:

  $ pipeline_check --config-check
  [config] OK -- no unknown keys.
  $ echo $?
  0

  $ pipeline_check --config-check  # with a typo
  [config] pyproject.toml: 'max_faillures' -- unknown key
  [config] 1 unknown key(s) detected.
  $ echo $?
  3
"""


OUTPUT = """\
TOPIC: output

--output FORMAT (default: terminal)
    terminal  Rich-formatted human report on stdout.
    json      Machine-parseable on stdout. Schema includes
              ``schema_version`` and ``tool_version`` for stable
              downstream parsing.
    html      Self-contained HTML on disk (--output-file required).
              Embedded CSS + JS; client-side filter bar (severity /
              standard / provider / status / free-text) and a
              per-finding "copy ignore" button.
    sarif     SARIF 2.1.0. Stdout by default; --output-file writes
              to disk. Best-effort startLine annotations land
              GitHub PR comments on the offending line; AWS ARN
              and region are exposed as result properties.
    both      Terminal report -> stderr, JSON -> stdout. Pipe
              ``jq`` while still seeing a human report.

--output-file PATH
    REQUIRED for --output html. Optional for --output sarif (default
    is stdout).

--severity-threshold SEV
    Minimum severity to include in the rendered report (e.g. HIGH
    hides MEDIUM/LOW/INFO). Does NOT affect the gate — the gate
    always evaluates the full finding set.

Examples
--------
# Pipe to jq while still seeing the rich terminal report
pipeline_check --output both 2>report.txt | jq '.score'

# SARIF for GitHub code scanning
pipeline_check --pipeline github --output sarif \\
    --output-file pipeline-check.sarif
# then in a workflow step:
#   github/codeql-action/upload-sarif with sarif_file: pipeline-check.sarif
"""


LAMBDA = """\
TOPIC: lambda

pipeline_check ships an AWS Lambda entry point at
``pipeline_check.lambda_handler.handler``. The same Scanner code
runs from CLI and Lambda — no behavioural divergence.

Build the package
-----------------
    bash scripts/build_lambda.sh
    # produces dist/pipeline_check-lambda.zip

Environment variables
---------------------
PIPELINE_CHECK_RESULTS_BUCKET
    S3 bucket for JSON reports. Stored under
    reports/<timestamp>/pipeline_check-report.json.
    Unset -> report not persisted; report_s3_status is "unconfigured".

PIPELINE_CHECK_SNS_TOPIC_ARN
    SNS topic alerted when CRITICAL findings are detected. Unset
    -> no alert ever sent.

Event payload
-------------
Single scan (legacy):
    {"region": "eu-west-1"}

Fan-out (multiple regions / providers in one invocation):
    {"regions": ["us-east-1", "eu-west-1"], "providers": ["aws"]}

Per-provider kwargs (tf_plan, gha_path, gitlab_path, bitbucket_path,
azure_path, jenkinsfile_path, target, profile) are forwarded to
Scanner alongside ``region`` / ``provider``.

Return value
------------
Single scan:
    {
      "statusCode": 200,
      "grade": "B",
      "score": 78,
      "total_findings": 22,
      "critical_failures": 0,
      "report_s3_key": "...",
      "report_s3_status": "ok" | "unconfigured" | "error"
    }

Fan-out:
    {
      "statusCode": 200,
      "scans": [{region, provider, grade, score, ...}, ...],
      "worst_grade": "D",
      "total_critical_failures": 3
    }

A per-scan exception produces an error entry instead of aborting
the whole invocation; ``worst_grade`` is forced to "D" when any
scan fails.

IAM
---
The bundled function needs read-only access to: codebuild,
codepipeline, codedeploy, ecr, iam, s3 (Get* only), plus
SNS:Publish + S3:PutObject for its own outputs. Full policy in
the top-level README.
"""


RECIPES = """\
TOPIC: recipes

Common end-to-end command lines, organised by the workflow you're
building.

PR gate (block on regressions only)
-----------------------------------
On main, capture the baseline:

    pipeline_check --pipeline aws --output json > baseline.json
    git add baseline.json && git commit -m "baseline: $(date +%F)"

On every PR:

    pipeline_check --pipeline aws \\
        --baseline-from-git origin/main:baseline.json \\
        --fail-on HIGH

Only HIGH+ findings NOT already in the baseline fail the gate.

Workflow PR scope
-----------------
    pipeline_check --pipeline github \\
        --diff-base origin/main \\
        --fail-on HIGH

Scans only the workflow files the PR changed.

Autofix on every PR
-------------------
    pipeline_check --pipeline github --fix --apply
    git diff --quiet || git commit -am "chore: pipeline_check autofix"

Pairs well with a "label: autofix-clean" PR check that fails when
``git diff`` is non-empty after the autofix run.

Compliance audit
----------------
    pipeline_check --standard-report nist_ssdf
    pipeline_check --standard-report owasp_cicd_top_10

Lists every control in the standard with the checks that map to
it, plus a "Gaps" section for controls with no mapped check.

Nightly drift detection
-----------------------
    pipeline_check --pipeline aws --region us-east-1 --output json \\
        | jq '.score.grade' \\
        | tee /tmp/grade.txt

Schedule via cron / EventBridge / GitHub Actions ``schedule``.
Diff against the previous grade to alert on regressions even
between PRs.

Investigation: which checks fire?
---------------------------------
    pipeline_check --pipeline github --severity-threshold INFO \\
        --output json | jq '.findings[] | select(.passed==false) | .check_id'

Filter for a specific provider via glob:

    pipeline_check --pipeline github --checks 'GHA-*'
    pipeline_check --pipeline github --checks '*-008'   # secret scans only
"""


INVENTORY = """\
TOPIC: inventory

Findings answer "what's wrong"; the inventory answers "what did the
scanner see". Useful for asset registers, drift detection, and audits
that need an independent record of what was in scope on a given date.

Flags
-----
--inventory
    Emit the component inventory alongside findings. Rendered as a
    compact table in terminal mode; added as an ``inventory`` array to
    JSON output. Absent from JSON when the flag isn't set — consumers
    can feature-detect.

--inventory-type PATTERN
    Glob filter on component type (repeatable). Implies --inventory.
    Case-sensitive: CloudFormation types are PascalCase
    (``AWS::IAM::*``), Terraform types are snake_case
    (``aws_iam_*``), workflow providers use lowercase (``workflow``,
    ``pipeline``, ``jenkinsfile``, ``config``). Match the casing of
    the provider you're slicing.

--inventory-only
    Skip check execution entirely; emit the inventory on its own.
    Useful for scheduled asset-register ingest. Mutually exclusive
    with --fix, --diff-base, and --baseline.

What each provider reports
--------------------------
AWS            codebuild_project, codepipeline, iam_role (CI/CD trust
               only), iam_user, cloudtrail_trail, secretsmanager_secret,
               codeartifact_domain / repository, codecommit_repository,
               lambda_function, kms_key, cloudwatch_log_group (under
               /aws/codebuild/*), ssm_parameter, eventbridge_rule,
               ecr_repository, ecr_pull_through_cache_rule, s3_bucket
               (artifact buckets only).
               Services that fail to enumerate surface as
               ``<service>_degraded`` rather than being silently
               omitted.

Terraform      Every planned aws_* resource. ``type`` is the HCL type
               (``aws_iam_role``), ``source`` is the Terraform address.

CloudFormation Every resource in the ``Resources:`` block. ``type`` is
               the PascalCase CFN type (``AWS::IAM::Role``).
               ``metadata`` preserves ``DeletionPolicy``,
               ``UpdateReplacePolicy``, and ``Condition``.

GitHub         One component per loaded workflow file. Metadata lists
               jobs, runners, environments, triggers, permissions.

GitLab / Bitbucket / Azure / CircleCI
               One component per pipeline / config file. Metadata
               depends on provider (jobs, categories, stages,
               workflows + orbs).

Jenkins        One component per parsed Jenkinsfile. Metadata lists
               stages, @Library refs, agent declaration, and whether
               the file declares a ``timeout`` or ``buildDiscarder``.

Examples
--------
Full inventory as JSON:

    pipeline_check --pipeline cloudformation --inventory \\
        --output json > inventory.json

Only the IAM surface:

    pipeline_check --pipeline cloudformation \\
        --inventory-type 'AWS::IAM::*' --output json

Asset-register ingest (no gate, no checks — just a snapshot):

    pipeline_check --pipeline aws --inventory-only --output json \\
        | jq '.inventory' > aws-assets-$(date +%F).json

Multiple type patterns (logical OR — any pattern match passes):

    pipeline_check --pipeline terraform --tf-plan plan.json \\
        --inventory-type 'aws_iam_*' --inventory-type aws_kms_key
"""


EXPLAIN = """\
TOPIC: explain

``--explain CHECK_ID`` prints the full reference for one check.
``--help`` lists every flag; ``--man TOPIC`` is the narrative per
subsystem; ``--explain`` is the narrative per check. All three are
orthogonal.

Use it when a finding fires in CI and you want to know *why this
specific rule* and *how to fix it* without grepping source or the
provider reference doc.

What it shows
-------------
  * Check ID, severity, and confidence (HIGH / MEDIUM / LOW).
  * Compliance cross-references for every standard this check
    evidences (OWASP Top 10 CI/CD, SLSA, NIST SSDF, ESF, ...).
  * CWE identifiers when the rule is tagged with them.
  * ``[What it checks]`` — the rule's docs note (rule-based
    providers) or a pointer to the provider doc (class-based
    modules like AWS core services).
  * ``[Known false-positive modes]`` — populated for rules whose
    heuristic shape is known to misfire on specific legitimate
    patterns. Use this to decide whether to dismiss a finding.
  * ``[How to fix]`` — the rule's recommendation string verbatim.

Exit codes
----------
  0  Explain succeeded.
  3  Unknown check ID (a suggestion list is printed first).

Examples
--------
    pipeline_check --explain GHA-024
    pipeline_check --explain CB-001
    pipeline_check --explain IAM-002

Tab completion (if installed via --install-completion) expands every
known check ID.
"""


_TOPICS: dict[str, str] = {
    "index": INDEX,
    "gate": GATE,
    "autofix": AUTOFIX,
    "diff": DIFF,
    "secrets": SECRETS,
    "standards": STANDARDS,
    "config": CONFIG,
    "output": OUTPUT,
    "inventory": INVENTORY,
    "lambda": LAMBDA,
    "recipes": RECIPES,
    "explain": EXPLAIN,
}


def topics() -> list[str]:
    """Return the public topic names (everything except the internal index)."""
    return [t for t in _TOPICS if t != "index"]


def render(topic: str) -> str:
    """Render a topic body. Unknown names render the index plus an error
    line so the user can correct the typo without an extra invocation.
    """
    name = (topic or "index").lower()
    body = _TOPICS.get(name)
    if body is None:
        return (
            f"Unknown topic: {topic!r}.\n\n"
            f"Available: {', '.join(topics())}\n\n"
            + INDEX
        )
    return body
