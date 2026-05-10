# Literal credentials

The most-easily-exploited mistake in CI: long-lived credentials
pasted directly into workflow YAML. The values land in every
fork, every clone, every build log, every search-engine cache,
and persist in git history indefinitely. Rotation requires
revoking the credential at the cloud provider — touching the
file alone leaves the leaked secret valid until then.

## Real-world incident

**Uber 2016 GitHub leak:** an AWS access key embedded in a
private GitHub repo was reachable to attackers who got at the
repo and used it to download driver / rider PII for 57 million
accounts. Credential-shaped literals in any source-control
system (public or private) are one credential-leak away from
the same outcome.

**GitGuardian State of Secrets Sprawl annual reports:**
consistently find millions of fresh credential leaks per year
across public commits, with median time-to-revocation measured
in days, not minutes.

## What the case demonstrates

  * GHA-008 catches the AKIA-prefixed AWS key, the AWS secret
    access key, and the ``ghp_``-prefixed PAT.
  * GHA-016 catches the ``curl ... | bash`` notify hook.

## Fix

Move credentials to GitHub Encrypted Secrets and reference via
``${{ secrets.NAME }}``. Better: use OIDC federation
(``aws-actions/configure-aws-credentials`` with
``role-to-assume:``) so no long-lived key exists at all. For the
notify hook: download, verify the SHA, then execute.
