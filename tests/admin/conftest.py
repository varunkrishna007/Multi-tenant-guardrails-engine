"""Admin API fixtures: a draft service over in-memory ports and the real authorizer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))  # guard_fixtures
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "policy"))  # policy_fixtures
