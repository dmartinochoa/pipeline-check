"""AC-027. Dockerfile bakes a credential file AND exposes a remote-access port.

Dockerfile-side analog of the supply-chain shapes in AC-009 and the
node-escape shapes in AC-011/020/023/025: two ``Dockerfile``
findings on the same image compose into "the image ships a key
**and** a way to reach it from the outside."

- **DF-019.** A ``COPY`` or ``ADD`` instruction sources a path
  whose name matches a credential file: ``id_rsa`` /
  ``id_ed25519`` / ``id_ecdsa`` / ``.npmrc`` / ``.pypirc`` /
  ``.aws/credentials`` / ``.kube/config``. The credential lands
  inside the image filesystem and survives every subsequent
  layer. Image registries replicate it (pulls / scans / mirrors),
  ``docker history`` exposes it, and any process inside a running
  container can read it.

- **DF-013.** An ``EXPOSE`` instruction declares a sensitive
  remote-access port: 22 (sshd), 23 (telnet), 21 (ftp), 3389
  (rdp), 5900 (vnc), or 3306 / 5432 / 6379 / 9200 / 27017
  (database / cache / search backends often left without auth in
  dev images). The image is shaped to run a network listener on
  that port; the orchestrator that runs it will publish it.

Combined: the image ships a private key (or registry / cloud
credential) **and** advertises a network listener that uses
exactly that auth class. An attacker who pulls a public mirror,
exfils a CI build artifact, or compromises a single running
container has both halves of the credential-and-listener pair, so
turning a stolen image into account access takes one ``ssh -i``
or one client connect.

Each leg has a clean fix that breaks the chain. Move the
credential out of the image (mount it at runtime via a Kubernetes
secret, AWS Secrets Manager, Vault, or container-level env)
**or** drop the EXPOSE for the remote-access daemon (the
container runtime's ``exec`` path covers every legitimate
operational use). Either fix is sufficient on its own; both is
defense in depth.

Reachability-model note: this chain stays on Dockerfile-level
co-occurrence (``group_by_resource`` over the same Dockerfile
path). A Dockerfile has no per-job structure — every instruction
runs in the single build context that produces one image, so
file-level co-location IS the reachability claim. The
``job_anchors`` intersection pattern doesn't apply.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-027",
    title="Image bakes a credential file AND exposes a remote-access port",
    severity=Severity.CRITICAL,
    summary=(
        "A ``Dockerfile`` ``COPY`` / ``ADD`` source path names a "
        "credential file (``id_rsa``, ``.aws/credentials``, "
        "``.npmrc``, ``.kube/config``, etc.: DF-019) AND the same "
        "image ``EXPOSE`` s a sensitive remote-access port (22, "
        "23, 21, 3389, 5900, common database / cache / search "
        "ports: DF-013). The image ships a key and a way to reach "
        "it from the outside; pulling a public mirror or exfiltrating "
        "a single CI build artifact yields both halves of the "
        "credential-and-listener pair."
    ),
    mitre_attack=(
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1078",      # Valid Accounts
        "T1190",      # Exploit Public-Facing Application
    ),
    kill_chain_phase="credential-access -> initial-access -> lateral-movement",
    references=(
        "https://docs.docker.com/build/building/best-practices/#exclude-with-dockerignore",
        "https://docs.docker.com/engine/security/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
    ),
    recommendation=(
        "Move the credential out of the image. Mount it at "
        "runtime: a Kubernetes secret (or projected SA token), "
        "AWS Secrets Manager / GCP Secret Manager / Vault for "
        "cloud creds, or a container-level env var sourced from "
        "the orchestrator. The image stops being a leak surface "
        "the moment the credential isn't baked in. Drop the "
        "``EXPOSE`` for the remote-access daemon: the container "
        "runtime's exec path (``docker exec`` / ``kubectl exec``) "
        "covers every legitimate debugging use without opening a "
        "port or shipping an extra daemon. Either fix breaks the "
        "chain on its own. Add a ``.dockerignore`` rule to keep "
        "credential files out of build context as a third layer; "
        "the COPY can't bake in what the build never sees."
    ),
    providers=("dockerfile",),
    triggering_check_ids=("DF-013", "DF-019"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["DF-013", "DF-019"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["DF-013"], ck_map["DF-019"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A ``COPY`` or ``ADD`` instruction sources a path "
            "whose name matches a credential file (DF-019): "
            "``id_rsa``, ``.npmrc``, ``.aws/credentials``, "
            "``.kube/config``, etc. The credential lands in the "
            "image filesystem and survives every subsequent layer; "
            "``docker history`` exposes it and image-registry "
            "mirrors replicate it.\n"
            "  2. The same image ``EXPOSE`` s a sensitive remote-"
            "access port (DF-013): SSH (22), telnet (23), RDP "
            "(3389), VNC (5900), FTP (21), or a database / cache / "
            "search port often shipped without auth in dev images. "
            "The image is shaped to run a network listener that "
            "uses exactly the auth class the credential authenticates "
            "for.\n"
            "  3. Combined: the image ships the key AND advertises "
            "a way to reach it from the outside. Anyone who pulls "
            "a public mirror, exfiltrates a CI build artifact, or "
            "compromises a single running container has both halves "
            "of the pair; turning a stolen image into account access "
            "takes one client connect. Move the credential out of "
            "the image (orchestrator-mounted secret, runtime env "
            "var) OR drop the EXPOSE for the remote-access daemon, "
            "either fix breaks the chain."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["DF-013", "DF-019"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
