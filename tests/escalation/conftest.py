"""Escalation tests: the guard, policy and admin fixtures of the neighbouring test packages."""

import sys
from pathlib import Path

for name in ("guard", "policy", "admin"):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / name))
