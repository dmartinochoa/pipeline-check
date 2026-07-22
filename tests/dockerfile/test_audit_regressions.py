"""Regression tests from the 2026-07 rule audit (Dockerfile)."""
from __future__ import annotations

from .conftest import run_check


def test_df016_legacy_space_form_label_counts_as_present():
    df = (
        "FROM alpine\n"
        "LABEL org.opencontainers.image.source \"https://e.com/r\"\n"
        "LABEL org.opencontainers.image.revision \"abc\"\n"
    )
    assert run_check(df, "DF-016").passed is True


def test_df017_writable_dir_at_tail_is_harmless():
    # A writable dir after the system bins doesn't shadow them.
    tail = "FROM alpine\nENV PATH=/usr/local/bin:/usr/bin:/bin:/tmp/bin\n"
    assert run_check(tail, "DF-017").passed is True
    # a writable dir before the system bins still shadows them
    first = "FROM alpine\nENV PATH=/tmp/bin:/usr/bin:/bin\n"
    assert run_check(first, "DF-017").passed is False
    # $PATH-tail form also passes
    path_tail = "FROM alpine\nENV PATH=\"${PATH}:/tmp/bin\"\n"
    assert run_check(path_tail, "DF-017").passed is True


def test_df019_json_array_copy_credential_file():
    json_form = "FROM alpine\nCOPY [\".npmrc\", \"/root/.npmrc\"]\n"
    assert run_check(json_form, "DF-019").passed is False
    shell_form = "FROM alpine\nCOPY .npmrc /root/.npmrc\n"
    assert run_check(shell_form, "DF-019").passed is False


def test_df012_sudo_in_echo_string_not_flagged():
    # A sudo mention inside an echoed string is not an invocation.
    echoed = "FROM alpine\nRUN echo \"please use sudo apt-get to install\"\n"
    assert run_check(echoed, "DF-012").passed is True
    # a real sudo invocation (at a command position) still fires
    real = "FROM alpine\nRUN sudo apt-get install -y jq\n"
    assert run_check(real, "DF-012").passed is False
    # sudo after a shell separator still fires
    chained = "FROM alpine\nRUN apt-get update && sudo apt-get install -y jq\n"
    assert run_check(chained, "DF-012").passed is False
