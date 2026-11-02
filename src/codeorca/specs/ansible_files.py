"""Reading Ansible vars files without ansible-core (pure, YAML only), the way Ansible finds and parses them.

Used to decide which markers the play scope hands over (``codeorca.steps.host_spec``) and which values the ansible
step registers before a play starts (``codeorca.steps.ansible``). Two rules matter for secrets:

- **A ``!vault`` value is opaque, never a parse failure.** A plain safe loader raises on the unknown tag, and a
  caller that swallowed the error lost every other key of that file (a denylist-named plain value next to one
  vaulted entry rendered in clear). :func:`load_vars_yaml` constructs ``!vault`` as :class:`VaultValue` and
  ``!unsafe`` as its string; any other tag is constructed as its plain node. A file that still does not parse
  raises :class:`VarsFileError`: callers fail closed (Ansible would fail on it too).
- **File discovery mirrors ansible-core 2.21.5**: :func:`find_vars_files` is ``DataLoader.find_vars_files`` (``''``
  first so a directory wins over ``name.yml``, the first hit wins, a directory is read recursively in sorted order,
  hidden and ``~`` files skipped); :func:`role_vars_files` is ``Role._load_role_yaml``'s order for ``defaults``/
  ``vars`` (``main.yml``, ``main.yaml``, ``main.json``, then ``main`` as a file or directory).

``ruamel``'s ``add_constructor`` is a classmethod on a dict shared by every loader in the process (the same trap as
``add_representer``, see AGENTS.md), so the constructor is a subclass assigned per ``YAML`` instance.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import SafeConstructor
from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode

VARS_EXTENSIONS = (".yml", ".yaml", ".json")
VAULT_MARKER = "<vault>"


class VarsFileError(RuntimeError):
    """A vars file that is not valid YAML even with the vault/unsafe tags understood."""


class VaultValue:
    """An opaque ``!vault`` value: never decrypted, never printed (``str`` is the ``<vault>`` marker)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return VAULT_MARKER

    __str__ = __repr__


class _AnsibleTagsConstructor(SafeConstructor):
    """``!vault`` -> :class:`VaultValue`, ``!unsafe`` -> its string, any other unknown tag -> its plain node."""


def _construct_vault(constructor, node):
    return VaultValue()


def _construct_unsafe(constructor, node):
    if isinstance(node, ScalarNode):
        return str(constructor.construct_scalar(node))
    return _construct_plain(constructor, node)


def _construct_plain(constructor, node):
    if isinstance(node, MappingNode):
        return constructor.construct_mapping(node, deep=True)
    if isinstance(node, SequenceNode):
        return constructor.construct_sequence(node, deep=True)
    return constructor.construct_scalar(node)


_AnsibleTagsConstructor.add_constructor("!vault", _construct_vault)
_AnsibleTagsConstructor.add_constructor("!unsafe", _construct_unsafe)


def _construct_tagged(constructor, _suffix, node):
    return _construct_plain(constructor, node)


_AnsibleTagsConstructor.add_multi_constructor("!", _construct_tagged)


def load_vars_text(text: str, origin: str = "<string>") -> Any:
    yaml = YAML(typ="safe", pure=True)
    yaml.Constructor = _AnsibleTagsConstructor
    try:
        return yaml.load(text)
    except Exception as exc:  # noqa: BLE001 - any parser error: the caller decides (fail closed)
        raise VarsFileError(f"{origin}: not readable as YAML ({type(exc).__name__})") from None


def load_vars_yaml(path: str | os.PathLike[str]) -> Any:
    """The file's data with ``!vault`` values as :class:`VaultValue`. A vault-ENCRYPTED file (``$ANSIBLE_VAULT;``)
    loads as one string: its names are unknowable here, which callers treat as "no candidates" (the play scope runs
    without a vault password, so Ansible cannot decrypt it either)."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise VarsFileError(f"{path}: cannot be read ({type(exc).__name__})") from None
    return load_vars_text(text, str(path))


def contains_vault(value: Any) -> bool:
    if isinstance(value, VaultValue):
        return True
    if isinstance(value, Mapping):
        return any(contains_vault(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(contains_vault(v) for v in value)
    return False


def _dir_vars_files(path: Path, extensions: Iterable[str]) -> list[Path]:
    found: list[Path] = []
    exts = tuple(extensions)
    for name in sorted(os.listdir(path)):
        if name.startswith(".") or name.endswith("~"):
            continue
        full = path / name
        ext = os.path.splitext(name)[1]
        if full.is_dir() and not ext:
            found.extend(_dir_vars_files(full, exts))
        elif full.is_file() and (not ext or ext in exts):
            found.append(full)
    return found


def find_vars_files(base: str | os.PathLike[str], name: str, extensions: Iterable[str] | None = None) -> list[Path]:
    """``DataLoader.find_vars_files(base, name)``: the first of ``name``, ``name.yml``, ``name.yaml``, ``name.json``
    (or the given extension order) that exists; a directory yields every vars file under it, recursively, sorted."""
    exts = ("", *VARS_EXTENSIONS) if extensions is None else tuple(extensions)
    joined = Path(base) / name
    for ext in exts:
        full = Path(f"{joined}{ext}") if ext.startswith(".") or not ext else Path(f"{joined}.{ext}")
        if full.is_dir():
            return _dir_vars_files(full, exts)
        if full.exists():
            return [full]
    return []


def role_vars_files(role_dir: str | os.PathLike[str], sub: str) -> list[Path]:
    """The files ``Role._load_role_yaml(sub)`` reads for ``defaults``/``vars``: ``main.yml``, ``main.yaml``,
    ``main.json``, then ``main`` (a file, or a directory read recursively)."""
    base = Path(role_dir) / sub
    if not base.is_dir():
        return []
    return find_vars_files(base, "main", (*VARS_EXTENSIONS, ""))


def load_mapping_files(paths: Iterable[Path]) -> Iterator[tuple[Path, dict[str, Any]]]:
    """``(path, mapping)`` for every file that holds a mapping (later files win when merged by the caller); a file
    that is not YAML raises :class:`VarsFileError`; an empty file or a non-mapping (an encrypted file) yields
    nothing."""
    for path in paths:
        data = load_vars_yaml(path)
        if isinstance(data, Mapping):
            yield path, {str(k): v for k, v in data.items()}


__all__ = [
    "VAULT_MARKER",
    "VarsFileError",
    "VaultValue",
    "contains_vault",
    "find_vars_files",
    "load_mapping_files",
    "load_vars_text",
    "load_vars_yaml",
    "role_vars_files",
]
