"""Write ``floor/rules.v2.json``: floor@2, the floor the held-out validation measured (M7-05).

    uv run python -m floor.derive_v2            # write floor/rules.v2.json
    uv run python -m floor.derive_v2 --check    # fail if the file differs from the derivation

floor@2 is ``floor/rules.json`` (floor@1) with the ``replacements`` of ``floor/next/additions.json``
substituted by key and its ``rules`` appended, at the additions' ``target_floor_version``. That is
what the calibration, held-out and red-team harnesses assemble in memory
(:func:`calibration.run.assemble_floor`, used here, so there is one definition), so the file's
content hash is the hash the harnesses report as ``floor_content_hash`` and the floor release
checks it against. Offline; sends nothing. ``floor/rules.json`` is never changed: its hash is
pinned and tenants' stored bundles extend it.

The engine loads ``rules.v2.json`` beside ``rules.json`` (``catalog.floor_files``). It is not
extendable by tenants until the platform releases it (two operators, with a live red-team report
of this floor; ``docs/m7-05-floor-2.md``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - run as a script
    sys.path.insert(0, str(ROOT))

from calibration.run import assemble_floor  # noqa: E402

RULES = ROOT / "floor" / "rules.json"
ADDITIONS = ROOT / "floor" / "next" / "additions.json"
OUT = ROOT / "floor" / "rules.v2.json"


def render(rules: Path = RULES, additions: Path = ADDITIONS) -> str:
    """The text of the floor@2 file: the assembled floor, two-space JSON like ``rules.json``."""
    return json.dumps(assemble_floor(rules, additions), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} differs from the derivation", file=sys.stderr)
            return 1
        print(f"ok: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
