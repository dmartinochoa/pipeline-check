"""GitLab pipeline run-history forensics provider.

Where the static ``gitlab`` provider reasons about what a ``.gitlab-ci.yml``
*could* do, this provider audits what *actually executed* by pulling recent
pipelines via the GitLab REST API (``GET /projects/:id/pipelines``).
"""
