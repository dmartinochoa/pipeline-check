"""Entry point for ``python -m pipeline_check``.

Mirrors the ``pipeline_check`` console script registered in
``pyproject.toml``. Lets users invoke the CLI without needing the
script to be on PATH (handy in fresh virtualenvs and in CI containers
where only ``python -m`` is reliably available).
"""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    main()
