# Fleet (org-wide) scanning

One repo at a time tells you whether *that* repo is safe. A fleet scan
tells you where the risk lives across an entire org, ranks the worst
offenders, and finds the attacks that only exist *between* repos.

`pipeline_check fleet` shallow-clones a set of repositories, scans each
one in a fresh subprocess (so per-repo state is fully isolated), and
writes a single graded digest plus the cross-repo attack chains that a
per-repo scan structurally cannot see.

## Two ways to pick the repos

### A repo list (`--repos`)

A YAML file of coordinates. Bare `owner/repo` defaults to GitHub;
prefix with `gitlab:` / `bitbucket:` (GitLab supports subgroups):

```yaml
# repos.yml
- dmartinochoa/pipeline-check
- gitlab:mygroup/mysubgroup/myproject
- bitbucket:workspace/slug
# or, with an explicit platform per entry:
- coord: another/repo
  platform: github
```

```bash
pipeline_check fleet --repos repos.yml
```

No token is needed for public repos; the clone uses plain HTTPS.

### A whole org (`--from-org`)

Enumerate every (non-archived) repo from an org / group / workspace via
the SCM API. This needs a token in the environment:

```bash
export GITHUB_TOKEN=...        # or GITLAB_TOKEN / BITBUCKET_TOKEN
pipeline_check fleet --from-org my-org --platform github
```

`--repos` and `--from-org` are mutually exclusive.

## Narrowing and tuning

| Flag | What it does |
|---|---|
| `--include GLOB` | Keep only repos whose name matches (repeatable, `fnmatch` syntax). |
| `--exclude GLOB` | Drop repos whose name matches (repeatable). Applied after discovery. |
| `--jobs N` | Repos to scan in parallel. `0` runs sequentially; omit to auto-detect from CPU and repo count. |
| `--scan-flags "..."` | Flags forwarded verbatim to every per-repo `pipeline_check` subprocess. Quote the whole value. |
| `--per-repo-timeout SEC` | Cap (clone + scan) per repo. A repo that exceeds it becomes a warning and the run continues. |
| `--output-dir PATH` | Where the digest tree lands (default `fleet-out`). |

`--scan-flags` is how you push scan options down to every repo, for
example to turn on the network-backed checks and pin a standard:

```bash
pipeline_check fleet --from-org my-org \
    --exclude '*-archive' --jobs 8 \
    --scan-flags '--standard owasp_cicd_top_10 --resolve-remote'
```

A single repo's clone or scan failure becomes a per-repo warning on the
digest, never an abort. You get the green-and-red breakdown across the
org even when one repo is misconfigured.

## What you get

```
fleet-out/
  <platform>/<owner>/<repo>/findings.json   # one full report per repo
  <platform>/<owner>/<repo>/scan.stderr     # captured warnings / errors
  fleet.json                                # machine-readable aggregate
  fleet.md                                  # human-readable digest
```

`fleet.md` is the page to open first. It ranks every repo worst-score
first, totals failed findings by severity across the org, and lists the
cross-repo chains. `fleet.json` carries the same data for scripting,
plus a **posture graph**.

### The posture graph

`fleet.json` includes a `posture_graph`: a plain adjacency that models
the org as nodes and edges.

- **Nodes** are the scanned repos, each carrying its grade, score, and
  per-severity failed-finding breakdown. A repo referenced by a
  cross-repo chain but not itself in the scanned set still lands as a
  node, flagged `scanned: false`, so an edge is never silently dropped.
- **Edges** are the cross-repo (`CXPC-NNN`) relationships: a directed
  `source -> target` link (the repo that carries the risk, then the
  partner repo that inherits it), tagged with the chain id, severity,
  and title.

```json
{
  "posture_graph": {
    "nodes": [
      {"id": "acme/shared-ci", "grade": "B", "score": 84, "total_failed": 2, "scanned": true},
      {"id": "acme/payments-api", "grade": "D", "score": 38, "total_failed": 12, "scanned": true}
    ],
    "edges": [
      {"source": "acme/shared-ci", "target": "acme/payments-api",
       "chain_id": "CXPC-002", "severity": "CRITICAL", "title": "..."}
    ]
  }
}
```

This is the same relationship data the commercial ASPM tools sell as
"pipeline topology," exposed as plain JSON you can render or query
however you like.

## Cross-repo attack chains

The reason a fleet scan beats running the scanner in a loop: the
`CXPC-NNN` chains fire *only* during a fleet scan, composing findings
from different repos in the same corpus. A tainted reusable workflow in
one repo plus a consumer in another, a freshly published npm package in
one repo plus a floating-version consumer in another, an Argo CD
wildcard `sourceRepos` plus a weak CI gate in a partner repo. None of
these is visible to a single-repo scan, because the two halves live in
different repositories.

See [Attack chains](attack_chains.md#cross-repo-chains-cxpc-nnn) for the
full `CXPC-NNN` catalog.

## Worked example

```bash
# Scan every repo in the org, in parallel, with the supply-chain
# network checks on, excluding archived mirrors.
export GITHUB_TOKEN=...
pipeline_check fleet --from-org acme \
    --exclude '*-mirror' --exclude '*-archive' \
    --jobs 8 \
    --scan-flags '--resolve-remote'

# Then read the ranked digest and the cross-repo edges.
less fleet-out/fleet.md
jq '.posture_graph.edges' fleet-out/fleet.json
```

## See also

- [Attack chains](attack_chains.md) — the `CXPC-NNN` cross-repo catalog.
- [Output](output.md) — the per-repo `findings.json` shape.
- [History dashboard](history.md) — `pipeline_check history` reads a
  fleet `--output-dir` directly (recursive `**/findings.json`) to chart
  posture trends over time.
