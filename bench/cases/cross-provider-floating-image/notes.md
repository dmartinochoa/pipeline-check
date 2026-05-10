# Cross-provider floating image

The textbook "tag mutability across build + runtime" pattern.
The Dockerfile pulls its base image by floating tag; the
Kubernetes manifest deploys the resulting image by floating
tag. Both ends are mutable. An attacker who controls the
upstream registry tag (compromised account, expired domain,
maintainer-account takeover) flips both:

  * The team's next image build runs against the new base
    bytes.
  * Every running pod re-pulls the new image bytes on the
    next schedule.

There is no compensating control on either side that breaks
the chain. Pinning either end alone narrows the surface;
pinning both closes it.

## Why this case exists

Pipeline-check's wedge against single-rule scanners is the
chain engine. Showing that the engine fires on a real
cross-provider composition — not just a contrived test
fixture — is the bench's most concrete coverage proof for the
correlation tier.

## What the case demonstrates

  * DF-001 catches the Dockerfile's ``FROM node:20``.
  * K8S-001 catches the manifest's ``image: my-org/api:1``.
  * XPC-002 fires on the (DF-001, K8S-001) pair as a single
    composite finding, with attribution naming both files.

## Fix

Pin both ends to ``@sha256:<digest>``. Capture the digest with
``crane digest`` (or ``docker buildx imagetools inspect``) and
update it deliberately in version control when the upstream
version moves. Configure ``imagePullPolicy: IfNotPresent`` on
the Kubernetes side so the kubelet doesn't re-resolve on every
pod restart.
