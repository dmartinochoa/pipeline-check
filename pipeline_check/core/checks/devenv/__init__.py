"""Developer-environment auto-execution provider.

Scans the config files that run code the moment a developer opens or
checks out the repository, a surface distinct from the pipeline
definitions the rest of the scanner covers:

- ``.vscode/tasks.json`` tasks with ``runOptions.runOn: folderOpen``
- ``.devcontainer/devcontainer.json`` lifecycle commands
  (``postCreateCommand`` and friends, plus the host-side
  ``initializeCommand``)
- ``.claude/settings.json`` Claude Code hooks that shell out

The threat is the second stage of campaigns like the 2026 Red Hat npm
compromise: a poisoned repo drops a loader that executes on
folder-open / devcontainer-create / agent-session-start, before any
build or test runs. ``DEV-NNN`` rules flag these auto-execution
surfaces and reserve CRITICAL for the remote-fetch-and-execute shape.
"""
