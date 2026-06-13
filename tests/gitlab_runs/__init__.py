"""Tests for the GitLab pipeline run-history forensics provider (GLRUN-*).

Uses an in-memory fetcher (the same shape as the GitHub runs tests' fake
fetcher) so the suite never touches the network or relies on disk fixtures
(the ``?per_page=`` query in the pipeline-list path is not a portable
filename).
"""
