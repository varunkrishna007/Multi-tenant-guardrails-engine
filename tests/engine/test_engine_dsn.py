"""M1-11 follow-up (decided 2026-11-17, required before the M1 live gate): a malformed
``GUARDRAIL_PG_DSN`` fails at startup, not on the first write, and the error never echoes the
DSN, which can hold a password. Malformed: surrounding whitespace, a control character, a
non-ASCII character (refused, never stripped, as for the API key), or not a
``postgresql://`` / ``postgres://`` URI."""

from __future__ import annotations

import logging
import random
import string

import pytest
from engine_fixtures import settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine, pg_dsn_problem

MARKER = "PgMrkW4x"
DSN_LENGTH = 181
"""Every bad DSN below is about this long, a number no message has a reason to contain."""


def password() -> str:
    rng = random.Random(1117)
    return MARKER + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40))


def dsn(offending: str = "", where: str = "end", scheme: str = "postgresql://") -> str:
    base = f"{scheme}u5t:{password()}@kq4m7:5432/wz8v"
    base += "x" * (DSN_LENGTH - len(base))  # pad the database name to the fixed length
    if where == "start":
        return offending + base
    if where == "end":
        return base + offending
    cut = base.index(MARKER) + 4
    return base[:cut] + offending + base[cut:]


def texts_of(exc: BaseException, caplog: pytest.LogCaptureFixture) -> list[str]:
    texts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        texts += [str(current), repr(current), *map(repr, current.args)]
        texts += [str(p) for p in getattr(current, "problems", [])]
        current = current.__cause__ or current.__context__
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    for record in caplog.records:
        texts += [formatter.format(record), repr(record.args), str(record.msg)]
    return texts


async def refused(monkeypatch, caplog, value: str) -> tuple[str, list[str]]:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", value)
    connected: list[str] = []
    monkeypatch.setattr(
        "guardrail_engine.store.adapters.postgres.connect_pool",
        lambda d: connected.append(d),
    )
    with pytest.raises(SettingsError) as raised:
        await build_engine(
            settings(store={"kind": "postgres"}), verifier=verifier(), model=FakeDecisionModel()
        )
    assert connected == []  # refused before any connection attempt
    [problem] = raised.value.problems
    return problem, texts_of(raised.value, caplog)


@pytest.mark.parametrize(
    ("offending", "where", "kind"),
    [
        ("\n", "end", "has surrounding whitespace"),
        ("\r\n", "end", "has surrounding whitespace"),
        (" ", "start", "has surrounding whitespace"),
        ("\t", "end", "has surrounding whitespace"),
        ("\x1b", "middle", "has a control character"),
        ("\x7f", "middle", "has a control character"),
        ("\N{LATIN SMALL LETTER E WITH ACUTE}", "middle", "has a non-ASCII character"),
        ("\N{NO-BREAK SPACE}", "end", "has surrounding whitespace"),
    ],
)
async def test_a_malformed_dsn_is_refused_at_startup_without_any_part_of_it(
    monkeypatch, caplog, offending, where, kind
):
    value = dsn(offending, where)
    problem, texts = await refused(monkeypatch, caplog, value)
    assert problem.startswith(f"GUARDRAIL_PG_DSN: {kind}")
    assert problem.endswith("it is refused, not stripped. Fix the stored secret")
    pieces = {value[i : i + 4] for i in range(len(value) - 3)}
    for text in texts:
        assert MARKER not in text
        assert str(len(value)) not in text and str(len(value.strip())) not in text
        assert not [p for p in pieces if p in text], "a 4-character piece of the DSN leaked"


@pytest.mark.parametrize("scheme", ["mysql://", "http://", "", "postgresql:/"])
async def test_a_dsn_that_is_not_a_postgres_uri_is_refused(monkeypatch, caplog, scheme):
    value = dsn(scheme=scheme)
    problem, texts = await refused(monkeypatch, caplog, value)
    assert problem == ("GUARDRAIL_PG_DSN: must be a postgresql:// (or postgres://) connection URI")
    for text in texts:
        assert MARKER not in text and password()[8:20] not in text


@pytest.mark.parametrize("scheme", ["postgresql://", "postgres://", "POSTGRESQL://"])
def test_a_well_formed_dsn_passes(scheme):
    assert pg_dsn_problem(dsn(scheme=scheme)) is None


async def test_a_well_formed_dsn_reaches_the_driver_unchanged(monkeypatch):
    value = dsn()
    seen: list[str] = []

    class Pool:
        async def close(self) -> None:
            pass

        def terminate(self) -> None:
            pass

    async def connect(d: str) -> Pool:
        seen.append(d)
        return Pool()

    monkeypatch.setattr("guardrail_engine.store.adapters.postgres.connect_pool", connect)
    monkeypatch.setenv("GUARDRAIL_PG_DSN", value)
    engine = await build_engine(
        settings(store={"kind": "postgres"}), verifier=verifier(), model=FakeDecisionModel()
    )
    await engine.shutdown()
    assert seen == [value]
