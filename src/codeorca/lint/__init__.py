"""Static lints over consumer content. ``codeorca.lint.ansible`` scans playbooks and role task files for the
secret-handling rules of plan section 5.5/5.7 (``hostvars`` dumps, secrets debugged or passed to plain module
parameters, redundant ``no_log``). A finding is a plain dict: ``{file, line, rule, level, message}``."""

from __future__ import annotations

from codeorca.lint.ansible import RULES, Finding, lint_playbooks

__all__ = ["RULES", "Finding", "lint_playbooks"]
