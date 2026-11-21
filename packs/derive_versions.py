"""Derive the packs' next versions from the 2026-11-19 live runs (M4-08, M5-04; decided 2026-11-19):
``insurance@3`` and ``energy@3`` (the re-measured thresholds), ``finance@2`` and ``healthcare@2``.

    uv run python -m packs.derive_versions            # write packs/<pack>/pack.v<N>.json
    uv run python -m packs.derive_versions --check    # fail if a file differs from the derivation

Offline: reads the live records in ``calibration/results/`` and the pack files; sends nothing.

Each new version is its base version with **only** ``version``, ``block_at``, ``escalate_at`` and
``provisional`` changed: the questions, the criteria, the guard points, modes, severities and
``max_action`` are the base's, byte for byte (a test checks it). Every earlier version stays
byte for byte (the catalog is append-only).

* **Calibrated rules** (a run measured positives and the rule can block): the agreed midpoint
  ``block_at`` and ``escalate_at`` of :func:`calibration.write_results.ruled`, with the B2
  all-rows floor that leaves out another enforce-mode blocking rule's positives (decided
  2026-11-19).
* **Escalate-only rules** keep the base's thresholds (decided: recall first; ``block_at`` is inert).
* **A rule with no sendable positive** (``d__hc_dosage_advice``: not calibrated live) and a rule
  the run did not re-measure keep the base's thresholds.
* **Every rule stays ``provisional: true``**: the evidence is in-sample, synthetic and
  template-heavy, with no held-out check and no real traffic.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - run as a script
    sys.path.insert(0, str(ROOT))

NEW_VERSIONS: dict[tuple[str, int], tuple[int, str]] = {
    # (pack, new version): (base version, the run whose records give the thresholds)
    ("insurance", 3): (2, "m4-08-insurance-v2-remeasure-r3"),
    ("energy", 3): (2, "m4-08-energy-v2-remeasure-r3"),
    ("finance", 2): (1, "m5-04-finance-live-3"),
    ("healthcare", 2): (1, "m5-04-healthcare-live-r2"),
}
NOT_CALIBRATED_LIVE = {"d__hc_dosage_advice"}
"""Rules with no sendable positive row (every firing row is withheld): nothing was
measured, so the base's thresholds stand and the docs say so."""


def pack_file(pack: str, version: int) -> Path:
    return ROOT / "packs" / pack / ("pack.json" if version == 1 else f"pack.v{version}.json")


def derive(pack: str, version: int) -> dict[str, Any]:
    from calibration import write_results

    base_version, run = NEW_VERSIONS[(pack, version)]
    doc = copy.deepcopy(json.loads(pack_file(pack, base_version).read_text(encoding="utf-8")))
    assert doc["version"] == base_version
    doc["version"] = version
    suggested = write_results.suggestions(run)
    for rule in doc["rules"]:
        key = rule["key"]
        found = suggested.get(key)
        if found is not None and "no positive" in (found.get("basis") or ""):
            # A rule kept for want of a positive must be named as not calibrated live
            assert key in NOT_CALIBRATED_LIVE, f"{key}: no positive was measured; list it"
        if (
            found is not None
            and found.get("basis") == "midpoint rule"
            and rule.get("max_action") != "escalate"
        ):
            rule["block_at"], rule["escalate_at"] = found["block_at"], found["escalate_at"]
        rule["provisional"] = True
    base = {
        r["key"]: r for r in json.loads(pack_file(pack, base_version).read_text("utf-8"))["rules"]
    }
    for key in NOT_CALIBRATED_LIVE & base.keys():  # and a listed rule keeps its base's values
        new = next(r for r in doc["rules"] if r["key"] == key)
        assert (new["block_at"], new["escalate_at"]) == (
            base[key]["block_at"],
            base[key]["escalate_at"],
        ), key
    return doc


def text_of(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    bad = []
    for pack, version in NEW_VERSIONS:
        path = pack_file(pack, version)
        text = text_of(derive(pack, version))
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                bad.append(str(path))
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path}")
    if bad:
        print(
            "out of date (run python -m packs.derive_versions):", *bad, sep="\n  ", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
