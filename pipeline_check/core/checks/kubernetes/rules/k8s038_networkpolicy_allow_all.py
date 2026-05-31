"""K8S-038. NetworkPolicy with overly broad allow rule (empty from / to)."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-038",
    title="NetworkPolicy ingress / egress allows all sources or destinations",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG",),
    cwe=("CWE-284",),
    recommendation=(
        "Replace the empty ``from: []`` / ``to: []`` rule with an "
        "explicit ``from: [{podSelector: {matchLabels: {…}}}]`` or "
        "``from: [{namespaceSelector: {matchLabels: {…}}}]`` that "
        "names the legitimate peer. An empty ``from`` / ``to`` peers "
        "list means *every* source / destination, every pod in "
        "every namespace, plus every external IP. This is "
        "indistinguishable from having no NetworkPolicy at all for "
        "the targeted pod, but visually appears to enforce a policy "
        "(the false-sense-of-security failure mode is worse than no "
        "policy)."
    ),
    docs_note=(
        "K8S-032 covers the absence of a default-deny NetworkPolicy. "
        "This rule covers the inverse: a NetworkPolicy that exists "
        "but contains an ``ingress:`` rule with no ``from:`` (allow "
        "from all) or no ``ports:`` filter, or an ``egress:`` rule "
        "with no ``to:`` filter. The ``from: []`` / ``to: []`` "
        "shorthand is the canonical mistake. A rule that lists "
        "specific peers via ``podSelector`` / ``namespaceSelector`` "
        "/ ``ipBlock`` passes."
    ),
    known_fp=(
        "Policies intentionally allowing world traffic to a public "
        "ingress controller pod ({app: nginx-ingress, public: "
        "true}). Add ``# pipeline-check: ignore K8S-038`` on the "
        "specific NetworkPolicy if the wide-open shape is "
        "deliberate.",
    ),
    exploit_example=(
        "# Vulnerable: a NetworkPolicy whose ingress rule has empty from:.\n"
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  podSelector:\n"
        "    matchLabels: { app: web }\n"
        "  ingress:\n"
        "    - from: []        # empty = allow from EVERY source\n"
        "\n"
        "# Attack: an empty `from:` matches every pod in every namespace\n"
        "# plus every external IP, so the policy enforces nothing while\n"
        "# looking like a control. Any compromised pod in the cluster\n"
        "# reaches `web` directly, the lateral-movement path the policy\n"
        "# was supposed to close.\n"
        "\n"
        "# Safe: name the legitimate peer explicitly.\n"
        "  ingress:\n"
        "    - from:\n"
        "        - podSelector:\n"
        "            matchLabels: { app: api-gateway }"
    ),
)


def _peers_empty(rule: Any, peer_field: str) -> bool:
    """Return True when *rule* would match every peer.

    A rule with ``from`` / ``to`` set to an empty list (`[]`) matches
    every peer (Kubernetes semantics for an empty peers list inside a
    policy rule). A rule that omits the field entirely also matches
    every peer. A rule with explicit peers is fine.
    """
    if not isinstance(rule, dict):
        return False
    peers = rule.get(peer_field)
    # Field absent -> rule matches every peer.
    if peers is None:
        return True
    # Field present but empty list -> rule matches every peer.
    if isinstance(peers, list) and not peers:
        return True
    return False


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "NetworkPolicy":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        for direction, peer_field in (("ingress", "from"), ("egress", "to")):
            rules = spec.get(direction)
            if not isinstance(rules, list):
                continue
            for idx, rule in enumerate(rules):
                if not _peers_empty(rule, peer_field):
                    continue
                offenders.append(
                    f"NetworkPolicy/{m.name} {direction}[{idx}] "
                    f"({peer_field}: <empty/missing> = allow-all)"
                )
                line = _line_of(rule) or _line_of(rules) or _line_of(spec)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "Every NetworkPolicy ingress / egress rule names explicit peers."
        if passed else
        f"{len(offenders)} NetworkPolicy rule(s) match every peer: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
