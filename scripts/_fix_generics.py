"""One-off helper used during the disallow_any_generics annotation
pass. Mechanically rewrites bare ``dict`` / ``list`` annotations in
function signatures and return types to their parameterized forms.

Skips the four AWS modules that are exempted via the boto3 mypy
override block. Those wrap ``Any`` from boto3 returns and adding
explicit type parameters there would be noise.

This script is intentionally conservative: it only touches positions
where a parameter name precedes ``: dict`` / ``: list`` or ``->``
precedes the bare type. Anything more contextual (nested generics,
local variable annotations) is left for hand-editing.
"""
from __future__ import annotations

import re
from pathlib import Path

PATTERNS = [
    (re.compile(r'(: )dict( *[,)=\]\n])'), r'\1dict[str, Any]\2'),
    (re.compile(r'(: )list( *[,)=\]\n])'), r'\1list[Any]\2'),
    (re.compile(r'(-> )dict( *[:\n])'), r'\1dict[str, Any]\2'),
    (re.compile(r'(-> )list( *[:\n])'), r'\1list[Any]\2'),
    (re.compile(r'\blist\[dict\](?!\[)'), r'list[dict[str, Any]]'),
    (re.compile(r'\bdict\[str, dict\](?!\[)'), r'dict[str, dict[str, Any]]'),
]

EXCLUDE = {
    Path('pipeline_check/core/checks/aws/_catalog.py'),
    Path('pipeline_check/core/checks/aws/workflows.py'),
    Path('pipeline_check/core/checks/aws/base.py'),
    Path('pipeline_check/core/providers/aws.py'),
}


def ensure_any_import(text: str) -> str:
    """Add ``Any`` to typing import (or create one) if any pattern uses it."""
    if 'Any' not in text:
        return text
    typing_re = re.compile(r'^from typing import (.*)$', re.M)
    m = typing_re.search(text)
    if m:
        names = m.group(1)
        # split-and-strip so ' Any' (post-comma whitespace) is matched
        # against the literal 'Any'; deduplicate while preserving order
        # so re-running the script doesn't grow ``Any, Any, Any...``.
        names_list = [n.strip() for n in names.split(',') if n.strip()]
        if 'Any' in names_list:
            return text
        unique_names = ['Any'] + [n for n in names_list if n != 'Any']
        return typing_re.sub(
            f'from typing import {", ".join(unique_names)}',
            text, count=1,
        )
    if 'from __future__ import annotations' in text:
        return text.replace(
            'from __future__ import annotations',
            'from __future__ import annotations\n\nfrom typing import Any',
            1,
        )
    return text


def main() -> None:
    for p in Path('pipeline_check').rglob('*.py'):
        if Path(*p.parts) in EXCLUDE:
            continue
        text = p.read_text(encoding='utf-8')
        new_text = text
        for pat, repl in PATTERNS:
            new_text = pat.sub(repl, new_text)
        if new_text != text:
            new_text = ensure_any_import(new_text)
            p.write_text(new_text, encoding='utf-8')
            print(f'edited: {p}')


if __name__ == '__main__':
    main()
