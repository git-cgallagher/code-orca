"""code-orca: Terraform + Ansible orchestrator driven by YAML workflows."""

from importlib.metadata import PackageNotFoundError, version

# pyproject.toml is the only version source: a release bump that forgot a second copy here failed the image smoke test.
try:
    __version__ = version("code-orca")
except PackageNotFoundError:  # a source tree that was never installed
    __version__ = "0.0.0+unknown"
