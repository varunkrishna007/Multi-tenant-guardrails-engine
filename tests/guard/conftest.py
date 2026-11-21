"""The Guard Service tests reuse the policy tests' catalog document builders
(``make_floor``, ``floor_rule``, ``make_pack``, ``pack_rule``), as the store tests do."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures
