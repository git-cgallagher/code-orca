"""Planted next to uses_json.py: under ``python -I`` the script's directory is not on sys.path, so this never runs."""

raise RuntimeError("planted json.py was imported: the helper is not running isolated")
