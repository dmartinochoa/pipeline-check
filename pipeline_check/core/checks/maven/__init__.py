"""Maven (``pom.xml``) supply-chain rule pack.

Mirrors the shape of the ``npm`` / ``pypi`` packs: a context object
holds the parsed ``pom.xml`` documents, each rule module exports a
``RULE`` plus a ``check()`` callable, and the orchestrator in
``pipelines.py`` auto-discovers rules under ``rules/``.

Gradle (``build.gradle`` / ``build.gradle.kts``) is a separate
ecosystem with its own DSL and lockfile shape; a future ``gradle``
provider will mirror this layout once the parser surface stabilizes.
"""
