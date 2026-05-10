# Kubernetes blast radius

A workload deployed with hostPath access, root-running container,
no security context, AND a service account bound to
cluster-admin. Each of the four legs is bad on its own; together
they collapse the attacker primitive from "compromise the app"
to "compromise the cluster."

## Real-world incident

**CVE-2021-25741** (Kubernetes subpath symlink escape): a
container with hostPath plus subpath could traverse outside the
volume boundary and read or modify arbitrary host files.
Exploitable on any cluster permitting hostPath to non-system
workloads.

**TeamTNT / Kinsing crypto-jacking campaigns (2020–2022):**
cluster compromise reports repeatedly traced lateral movement
from a single misconfigured pod to the underlying node via
``hostPath: /``, then to kubelet credentials and other tenants.
Sysdig and Aqua incident reports document the pattern across
hundreds of confirmed compromises.

## What the case demonstrates

  * K8S-013 catches the hostPath volume.
  * K8S-001 catches the floating-tag image.
  * K8S-005 / K8S-006 / K8S-007 catch the missing securityContext
    knobs (runAsNonRoot, allowPrivilegeEscalation,
    readOnlyRootFilesystem).
  * K8S-020 catches the cluster-admin role binding.

The composite is exactly what AC-011 (Kubernetes Cluster
Takeover via hostPath + cluster-admin) was built around.

## Fix

Drop the hostPath volume. Configure ``securityContext.runAsNonRoot:
true``, ``allowPrivilegeEscalation: false``, and
``readOnlyRootFilesystem: true``. Replace the cluster-admin
binding with a least-privilege Role scoped to the namespace and
the resources the workload actually needs. Pin the image to a
digest.
