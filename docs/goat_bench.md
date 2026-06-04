# GOAT bench

Pipeline-check ships a regression gate that runs the scanner
against a corpus of pinned, vulnerable-by-design CI/CD and IaC
testbeds, then asserts the rule pack still fires on the
misconfigurations each testbed is intended to teach. It's the
proof that "this scanner catches the things it claims to catch" on
real-world surface area, not just on the synthetic
[`bench/cases/`](https://github.com/dmartinochoa/pipeline-check/tree/master/bench/cases)
fixtures.

Live status: [GOAT bench
workflow](https://github.com/dmartinochoa/pipeline-check/actions/workflows/goat-bench.yml).

## Current state

| Goat | Recall | Findings | Coverage |
|---|---|---|---|
| [`cicd-goat`](https://github.com/cider-security-research/cicd-goat) | **9 / 9 (100%)** | 28 | GHA release workflow + 7 Jenkinsfiles |
| [`cicd-goat-comparison`](https://github.com/greylag-ci/cicd-goat) | **27 / 27 (100%)** | - | GHA + npm slice of the 120-scenario cross-scanner matrix (pipeline-check leads) |
| [`cfngoat`](https://github.com/bridgecrewio/cfngoat) | **6 / 6 (100%)** | 7 | `cfngoat.yaml` (IAM, KMS, Lambda, CloudTrail) |
| [`kubernetes-goat`](https://github.com/madhuakula/kubernetes-goat) | **27 / 27 (100%)** | 27 | `scenarios/` manifest tree |
| [`terragoat`](https://github.com/bridgecrewio/terragoat) | pending curation | - | Direct-HCL parsing shipped; `expected.txt` awaiting population |

**42 check IDs locked across the three fully curated goats.** Any rule
change that stops one from firing on its goat trips the bench in
CI. The `cicd-goat-comparison` goat gates the GHA + npm slice with 27
unique curated check IDs; upstream that testbed has since grown into a
120-scenario, 16-provider cross-scanner matrix that Pipeline-Check
leads (see below).

## How it works

[`bench/goats.yml`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats.yml)
declares the corpus. The runner
([`bench/goat_runner.py`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goat_runner.py))
shallow-clones each goat into a tmpdir, runs pipeline-check with
the provider mix declared per goat (Jenkinsfile discovery is
globbed automatically when `jenkins` is in the goat's pipeline
list), and diffs findings against three committed inputs per goat:

* `bench/goats/<slug>/expected.txt` — hand-curated check IDs the
  goat is intended to teach. Each entry maps to a documented
  challenge or CIS benchmark control. Missing one fails the bench.
* `bench/goats/<slug>/allowlist.txt` — known false positives, with
  a one-line justification each. Allowlisted IDs don't gate.
* `bench/goats/<slug>/baseline.json` — the last committed scan
  output. Drift in either direction (new findings, resolved
  findings) surfaces in the report; unallowlisted new findings
  also gate.

CI runs nightly on `master` and on every PR that touches the rule
pack, the chain engine, or the bench code. PRs get a sticky
comment with the per-goat delta; every run uploads the full report
as a `goat-bench-report` workflow artifact for download.

## Reproducing locally

```bash
git clone https://github.com/dmartinochoa/pipeline-check
cd pipeline-check
pip install -e .

# Full corpus
python bench/goat_runner.py --markdown

# One goat
python bench/goat_runner.py --goat cfngoat --json
```

Each clone is shallow (`--depth 1`). cicd-goat is the largest at
~5000 files; the full bench runs in 1-2 minutes. Exit code 0 means
every scannable goat hit 100% recall on its curated expected list
and no new findings appeared against the baseline that weren't
allowlisted.

## Per-goat curation

Each goat's `expected.txt` documents the mapping from fired check
IDs to the goat's intended teaching.

### cicd-goat — OWASP CI/CD Top 10

The seven Alice-in-Wonderland challenges
([`solutions/`](https://github.com/cider-security-research/cicd-goat/tree/main/solutions))
are anchored against specific CICD-SEC risks:

| Check ID | OWASP CICD-SEC | Goat scenario |
|---|---|---|
| `GHA-003` | SEC-4 PPE | `release.yaml`: script injection via `${{ github.event.* }}` |
| `GHA-014` | SEC-1 | Deploy missing `environment:` binding |
| `GHA-015` | SEC-7 | Deploy missing `timeout-minutes` |
| `JF-003`  | SEC-5 / SEC-7 | `agent any` (drives cheshire-cat's Direct-PPE-to-Controller) |
| `JF-005`  | SEC-1 | caterpillar deploy missing manual `input` |
| `JF-011`  | SEC-10 | No `buildDiscarder` retention |
| `JF-015`  | SEC-7 | No `timeout {}` wrapper |
| `JF-028`  | SEC-9 | caterpillar + reportcov publish without SLSA (dormouse's Codecov-style scenario) |
| `JF-030`  | SEC-1 | mock-turtle dangerous shell idiom (auto-merge bypass) |

[Full `expected.txt`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats/cicd-goat/expected.txt)

### cicd-goat-comparison — 120-scenario cross-scanner matrix

[`greylag-ci/cicd-goat`](https://github.com/greylag-ci/cicd-goat) is a
purpose-built testbed for cross-scanner comparison: 120 scenarios
across 16 providers and formats, each isolating one CI/CD or IaC
vulnerability with a minimal fixture. It scores nine scanners head to
head (pipeline-check, Checkov, KICS, Trivy, zizmor, poutine, octoscan,
ciguard, actionlint).

On the 43 GitHub Actions scenarios, where the GHA-specialist scanners
compete directly, Pipeline-check leads by a wide margin:

| Scanner | GHA scenarios |
|---|---|
| **pipeline-check** | **37 / 43** |
| zizmor | 17 / 43 |
| poutine | 14 / 43 |
| octoscan | 13 / 43 |
| Checkov | 10 / 43 |
| KICS | 8 / 43 |
| actionlint | 6 / 43 |

Across all 16 categories Pipeline-check is the top scorer in 14 and the
sole leader in 11: GitHub Actions, GitLab CI (14/14), Azure Pipelines
(7/7), CircleCI (6/7), Bitbucket Pipelines (7/7), Jenkins (4/6), Tekton
(4/4), Argo (5/5), Drone (3/3), Buildkite (2/2), and Cloud Build (2/2).
It ties Trivy for first on Dockerfile, Kubernetes, and Helm (3/3 each).
Terraform and CloudFormation are scored only for the IaC scanners
(Checkov, KICS, Trivy), which lead there.

The local GOAT bench gates a slice of this corpus: the runner scans the
GHA + npm scenarios and asserts 27 curated check IDs still fire, so a
rule regression that would cost Pipeline-check its leaderboard standing
trips CI here first. The full per-scenario expected values for every
scanner live in
[`tools/scenarios.yaml`](https://github.com/greylag-ci/cicd-goat/blob/main/tools/scenarios.yaml)
in the goat repo.

[Full `expected.txt`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats/cicd-goat-comparison/expected.txt)

### cfngoat — vulnerable AWS CloudFormation

Every fire maps to a misconfiguration on `cfngoat.yaml`:

| Check ID | Misconfiguration |
|---|---|
| `CF-001`  | `AWS::IAM::AccessKey` long-lived static credential as code |
| `CT-001`  | Stack deploys AWS resources with no `AWS::CloudTrail::Trail` (CIS AWS 3.1) |
| `KMS-001` | `KMS::Key.LogsKey` rotation disabled (CIS AWS 3.8) |
| `KMS-002` | `KMS::Key.LogsKey` policy grants wildcard `kms:*` (CIS AWS 1.16) |
| `LMB-001` | AnalysisLambda + CleanBucketFunction lack `CodeSigningConfigArn` (CIS SSC 2.4.2) |
| `LMB-003` | AnalysisLambda env vars carry plaintext secret-shaped values (CIS AWS 3.7) |

[Full `expected.txt`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats/cfngoat/expected.txt)

### kubernetes-goat — vulnerable K8s cluster + workloads

27 check IDs grouped by attack pattern, each mapped to one of the
goat's 22 documented scenarios or the CIS Kubernetes Benchmark
coverage the goat's "K8s CIS benchmarks analysis" challenge is
explicitly demonstrating:

* **Container escape** (challenges 2 + 4): `K8S-002/003/004`
  (hostNetwork/PID/IPC), `K8S-005` (privileged), `K8S-013/014`
  (hostPath / sensitive hostPath).
* **Privilege escalation / root hardening**: `K8S-006`
  (allowPrivilegeEscalation), `K8S-007/035` (runAsNonRoot /
  runAsUser 0), `K8S-009` (capabilities).
* **Sandboxing defense-in-depth**: `K8S-008` (readOnlyRootFilesystem),
  `K8S-010` (seccompProfile).
* **ServiceAccount token surface** (challenge 12): `K8S-011/012/034`.
* **RBAC** (challenge 16): `K8S-020` (cluster-admin binding).
* **Sensitive credentials** (challenge 1): `K8S-018` (Secret literals).
* **Namespace / network isolation** (challenges 11 + 20):
  `K8S-019/023/031/032`.
* **Image supply chain** (challenges 7, 15): `K8S-001` (unpinned digest).
* **DoS / resource exhaustion** (challenge 13): `K8S-015/016`
  (resource limits), `K8S-033` (ResourceQuota).
* **Control-plane abuse**: `K8S-030`.
* **Operational hygiene**: `K8S-024` (probes).

[Full `expected.txt`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats/kubernetes-goat/expected.txt)

## terragoat status

[`bridgecrewio/terragoat`](https://github.com/bridgecrewio/terragoat)
is in the corpus and scans via `--tf-source terraform/aws`
(direct-HCL parsing shipped post-1.3.0). The goat entry in
[`bench/goats.yml`](https://github.com/dmartinochoa/pipeline-check/blob/master/bench/goats.yml)
is active but `expected.txt` has not yet been curated. The next
step is to run `python bench/goat_runner.py --goat terragoat
--suggest` and hand-curate the expected set against terragoat's
documented misconfigurations.

## Adding a goat

1. Add the goat to `bench/goats.yml` with a pinned `ref:` and the
   provider mix to scan.
2. `python bench/goat_runner.py --goat <slug> --suggest` writes a
   candidate `expected.txt` populated with every check ID the
   current scan fires.
3. Hand-curate `expected.txt` down to the IDs the goat is
   intended to teach. Document the mapping inline.
4. `python bench/goat_runner.py --goat <slug> --update-baseline`
   records the drift reference.
5. Commit `expected.txt`, `allowlist.txt` (empty is fine for now),
   and `baseline.json`.

The bench workflow picks the new goat up automatically.
