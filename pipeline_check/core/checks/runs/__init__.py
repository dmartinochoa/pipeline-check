"""GitHub Actions run-history forensics provider.

Where the static ``github`` provider reasons about what a workflow
*could* do, this provider audits what *actually executed* by pulling
recent Actions runs via the REST API.
"""
