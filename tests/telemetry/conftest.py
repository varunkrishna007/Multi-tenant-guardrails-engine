"""The telemetry tests run checks through the Guard Service test environment
(``tests/guard/guard_fixtures.py``), which uses the policy tests' document builders."""

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
for sub in ("guard", "policy"):
    if str(TESTS / sub) not in sys.path:
        sys.path.insert(0, str(TESTS / sub))
