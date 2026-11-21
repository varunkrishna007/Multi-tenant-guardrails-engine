"""The one token estimator the engine uses (AC-M1-6).

The fake model, the API limit checks, the policy compiler's token budget (AC-C1.8) and the
gateway's input-size band (R6.3) all call these functions, so the numbers they compare
agree. The compiler's budget applies the fitted R6.6 correction on top
(:mod:`guardrail_engine.policy.api_tokens`); this raw estimate is unchanged.

The rule is deterministic and deliberately conservative:

* every ASCII character counts as 1/4 token (English text averages about 4 characters per
  token), and
* every non-ASCII character counts as 1 whole token (CJK, emoji and accented text tokenise
  far less densely than English).

The total is rounded up. It is an estimate, not Gemini's tokenizer. Billing uses the
provider's ``usage`` figures, never this function.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol


class _WireModel(Protocol):
    def model_dump(self, *, mode: str, exclude_none: bool) -> dict: ...


def estimate_tokens(text: str) -> int:
    """Estimated tokens in ``text``: ceil(ascii_chars / 4) + non_ascii_chars.

    ASCII characters are counted in C (``encode`` with ``ignore`` drops exactly the
    characters at or above U+0080), because the gateway sizes every call's input with this
    function (R6.3): a per-character Python loop took about 20 ms on a 16K-token input."""
    ascii_chars = len(text) if text.isascii() else len(text.encode("ascii", "ignore"))
    return -(-ascii_chars // 4) + (len(text) - ascii_chars)


def estimate_question_tokens(questions: Mapping[str, _WireModel]) -> int:
    """Estimated tokens for a ``questions`` object as it is sent on the wire.

    Each question is serialised as its compact JSON ``{key: question}`` entry, so keys,
    instructions, criteria and the JSON structure all count.
    """
    return sum(
        estimate_tokens(
            json.dumps(
                {key: q.model_dump(mode="json", exclude_none=True)},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        for key, q in questions.items()
    )
