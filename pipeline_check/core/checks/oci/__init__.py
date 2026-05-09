"""OCI image artifact provider, parses image manifests / image-indexes
captured via ``docker buildx imagetools inspect --raw <ref>`` (or
equivalent ``oras manifest fetch`` output).

Pure parser, no registry pull, no image build, no daemon access. Each
input file is a JSON document conforming to one of:

  * ``application/vnd.oci.image.manifest.v1+json`` — single-platform
    image manifest, has ``config`` + ``layers``.
  * ``application/vnd.oci.image.index.v1+json`` — multi-platform
    image index, has ``manifests`` listing per-platform manifests
    and (typically) sibling attestation manifests.
  * The Docker-distribution-v2 equivalents
    (``application/vnd.docker.distribution.manifest.list.v2+json``
    and ``application/vnd.docker.distribution.manifest.v2+json``),
    which BuildKit / buildx still emit by default. These are
    parsed identically; rules treat them as compatible with the
    OCI shape.

The provider is opt-in (``--pipeline oci``), no auto-detection — an
image manifest JSON sitting at cwd is rare enough that auto-picking
it would surprise users running other providers.
"""
