"""YAML loading for code-orca files.

YAML 1.2 via ruamel.yaml (pure mode): an unquoted ``on:`` stays the string "on". PyYAML would turn it into True.
The models still reject such keys, as belt and braces.
"""

from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML

from codeorca.models import Workflow


def load_yaml(path: str | Path):
    yaml = YAML(typ="safe", pure=True)
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh)


def load_workflow(path: str | Path) -> Workflow:
    return Workflow.model_validate(load_yaml(path))
