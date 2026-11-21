"""M4-07 what the audit query shows of a record."""

from audit_records import make_record

from guardrail_engine.audit.query import INTERNAL_DETAIL, present
from guardrail_engine.guard.verdict import Reason


def shown(record):
    import json

    return present(json.loads(record.model_dump_json()), frozenset())


def test_an_internal_error_shows_a_fixed_sentence_never_its_detail():
    """A lost floor rule's detail carries the catalog's thresholds and fail mode."""
    record = make_record("t_acmeins").model_copy(
        update={
            "reason": Reason.INTERNAL_ERROR,
            "detail": "floor rule lost: block_at 0.55 escalate_at 0.3 fail_mode=block",
        }
    )
    out = shown(record)
    assert out["reason"] == "internal_error" and out["detail"] == INTERNAL_DETAIL
    assert "0.55" not in str(out) and "fail_mode" not in str(out)


def test_other_details_are_shown_as_the_engine_wrote_them():
    record = make_record("t_acmeins").model_copy(
        update={"reason": Reason.INVALID_REQUEST, "detail": "conversation_id is not valid"}
    )
    assert shown(record)["detail"] == "conversation_id is not valid"
