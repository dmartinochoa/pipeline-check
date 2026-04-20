"""Attack-chain rule registry.

One module per chain — each exports ``RULE`` (a :class:`ChainRule`) and
a ``match(findings) -> list[Chain]`` callable. The engine auto-discovers
modules whose name doesn't start with an underscore.
"""
