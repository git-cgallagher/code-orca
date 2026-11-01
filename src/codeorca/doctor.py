"""``codeorca doctor``: compare ``project.runtime`` with the environment the process runs in (plan section 5.1).

Fails closed: any mismatch or missing tool is exit 1. ``terraform``, ``ansible_core`` and ``collections`` are
exact pins; ``python``, ``pwsh`` and ``python_packages`` accept a range. The range syntax is deliberately tiny
and dependency-free: ``1.2.3`` or ``==1.2.3`` (exact), ``>=3.13,<3.14`` (comma-joined comparators), ``7.6.*``
(prefix) and ``*`` (anything). Versions are compared on their leading dotted integers; a pre-release suffix
(``3.14.0rc1``) is ignored.

Probes are injectable (``probes={"terraform": lambda: "1.14.7", ...}``) so the matcher is tested without the
tools; the default probes shell out to ``terraform version -json``, ``ansible --version`` /
``importlib.metadata``, ``pwsh -NoProfile -Command ...`` and ``ansible-galaxy collection list --format json``.
"""

from __future__ import annotations

import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from codeorca.project import Runtime

Probe = Callable[[], Any]
_VERSION = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")
_COMPARATOR = re.compile(r"^(>=|<=|==|!=|>|<)?\s*(.+)$")
EXACT = ("terraform", "ansible_core", "collections")
RANGE = ("python", "pwsh", "python_packages")


class VersionSpecError(ValueError):
    pass


def parse_version(text: str | None) -> tuple[int, ...] | None:
    if text is None:
        return None
    m = _VERSION.match(str(text))
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    pa, pb = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


def matches(found: str | None, spec: str, exact: bool = False) -> bool:
    """True when ``found`` satisfies ``spec``. With ``exact`` the spec must be a plain version and equal."""
    spec = spec.strip()
    if found is None:
        return False
    if exact:
        want, got = parse_version(spec.removeprefix("==")), parse_version(found)
        return want is not None and got is not None and _cmp(got, want) == 0
    if spec == "*":
        return True
    fv = parse_version(found)
    if fv is None:
        return False
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        if part.endswith(".*"):
            prefix = parse_version(part[:-2])
            if prefix is None:
                raise VersionSpecError(f"bad version spec {spec!r}")
            if fv[: len(prefix)] != prefix:
                return False
            continue
        m = _COMPARATOR.match(part)
        if not m:
            raise VersionSpecError(f"bad version spec {spec!r}")
        op, want_text = m.group(1) or "==", m.group(2)
        want = parse_version(want_text)
        if want is None:
            raise VersionSpecError(f"bad version spec {spec!r}")
        c = _cmp(fv, want)
        ok = {">=": c >= 0, "<=": c <= 0, "==": c == 0, "!=": c != 0, ">": c > 0, "<": c < 0}[op]
        if not ok:
            return False
    return True


# ------------------------------------------------------------------------------------------------- probes


def _run(argv: list[str], timeout: float = 20.0) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def probe_terraform() -> str | None:
    out = _run(["terraform", "version", "-json"])
    if not out:
        return None
    try:
        return str(json.loads(out).get("terraform_version"))
    except ValueError:
        return None


def probe_ansible_core() -> str | None:
    try:
        return importlib.metadata.version("ansible-core")
    except importlib.metadata.PackageNotFoundError:
        pass
    out = _run(["ansible", "--version"])
    if not out:
        return None
    m = re.search(r"\[core ([^\]]+)\]", out)
    return m.group(1) if m else None


def probe_python() -> str:
    return platform.python_version()


def probe_pwsh() -> str | None:
    out = _run(["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
    return out.strip() if out else None


def probe_collections() -> dict[str, str] | None:
    out = _run(["ansible-galaxy", "collection", "list", "--format", "json"], timeout=60.0)
    if not out:
        return None
    try:
        listing = json.loads(out)
    except ValueError:
        return None
    found: dict[str, str] = {}
    for entries in listing.values():
        if isinstance(entries, dict):
            for fqcn, spec in entries.items():
                if isinstance(spec, dict) and spec.get("version") and fqcn not in found:
                    found[fqcn] = str(spec["version"])
    return found


def probe_python_packages(names: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in names:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = None
    return out


def default_probes(runtime: Runtime) -> dict[str, Probe]:
    return {
        "terraform": probe_terraform,
        "ansible_core": probe_ansible_core,
        "python": probe_python,
        "pwsh": probe_pwsh,
        "collections": probe_collections,
        "python_packages": lambda: probe_python_packages(sorted(runtime.python_packages)),
    }


# -------------------------------------------------------------------------------------------------- report


@dataclass
class Check:
    component: str
    expected: str
    found: str | None
    ok: bool
    kind: str  # exact | range

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "expected": self.expected,
            "found": self.found,
            "ok": self.ok,
            "status": "ok" if self.ok else ("missing" if self.found is None else "mismatch"),
            "kind": self.kind,
        }


def run_checks(runtime: Runtime, probes: Mapping[str, Probe] | None = None) -> tuple[list[Check], dict[str, Any]]:
    """``(checks, observed)``; ``observed`` is what ``--lock`` prints as a ``runtime:`` block."""
    probes = dict(probes or default_probes(runtime))
    checks: list[Check] = []
    observed: dict[str, Any] = {"image": runtime.image}

    def probe(name: str) -> Any:
        fn = probes.get(name)
        if fn is None:
            return None
        try:
            return fn()
        except Exception:  # noqa: BLE001 - a crashing probe is a missing tool
            return None

    for name in ("terraform", "ansible_core", "python", "pwsh"):
        expected = getattr(runtime, name)
        found = probe(name)
        found = str(found) if found is not None else None
        checks.append(Check(name, expected, found, matches(found, expected, exact=name in EXACT), _kind(name)))
        observed[name] = found

    collections = probe("collections")
    collections = dict(collections) if isinstance(collections, dict) else {}
    observed["collections"] = dict(sorted(collections.items()))
    for fqcn, expected in sorted(runtime.collections.items()):
        found = collections.get(fqcn)
        checks.append(Check(f"collections.{fqcn}", expected, found, matches(found, expected, exact=True), "exact"))

    packages = probe("python_packages")
    packages = dict(packages) if isinstance(packages, dict) else {}
    observed["python_packages"] = {k: v for k, v in sorted(packages.items()) if v is not None}
    for pkg, expected in sorted(runtime.python_packages.items()):
        found = packages.get(pkg)
        checks.append(Check(f"python_packages.{pkg}", expected, found, matches(found, expected), "range"))
    if runtime.collections_from_file:
        observed["collections_from_file"] = runtime.collections_from_file
    return checks, observed


def _kind(name: str) -> str:
    return "exact" if name in EXACT else "range"


def format_table(checks: list[Check]) -> str:
    rows = [("component", "expected", "found", "status")] + [
        (c.component, c.expected, c.found or "-", c.as_dict()["status"]) for c in checks
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    return "\n".join("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip() for r in rows)


def format_lock(observed: Mapping[str, Any]) -> str:
    """A ``runtime:`` YAML block of what was observed (null for a missing tool, so the file still validates
    only once a human fills it in)."""
    import io

    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    yaml.default_flow_style = False
    yaml.sort_base_mapping_type_on_output = False
    buf = io.StringIO()
    yaml.dump({"runtime": dict(observed)}, buf)
    return buf.getvalue()
