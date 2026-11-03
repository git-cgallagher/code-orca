"""Fixture helper: imports json (a planted json.py sits next to it) and reports which module it got."""

import json
import os

with open(os.environ["CODEORCA_OUTPUT_FILE"], "w", encoding="utf-8") as fh:
    json.dump({"json_module": json.__file__}, fh)
