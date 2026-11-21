# ruff: noqa: E501  (sentence bank: long strings)
"""Neutral filler for the held-out set's production-shaped examples (R7.3(b)).

Long content is composed deterministically from a bank of ordinary business sentences with
slots, so a 12K-token document doesn't repeat one paragraph over and over. The decisive span
(or, for a negative, nothing) is inserted at a chosen depth. Nothing here is decisive for any
floor rule: the bank is written to be clean for every floor@2 rule.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable

from guardrail_engine.tokens import estimate_tokens

NAMES = (
    "Priya Raman",
    "Tomasz Nowak",
    "Grace Okafor",
    "Daniel Reyes",
    "Hannah Becker",
    "Kwame Mensah",
    "Sofia Rossi",
    "Liam O'Connor",
    "Mei Lin",
    "Omar Haddad",
    "Ingrid Larsen",
    "Ravi Patel",
    "Chloe Martin",
    "Yusuf Demir",
    "Aoife Byrne",
)
CITIES = (
    "Leeds",
    "Bristol",
    "Cardiff",
    "Glasgow",
    "Norwich",
    "Exeter",
    "York",
    "Belfast",
    "Swansea",
    "Derby",
    "Bath",
    "Inverness",
)
MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
PRODUCTS = (
    "home insurance",
    "the fixed-rate tariff",
    "the business current account",
    "contents cover",
    "the smart meter programme",
    "travel insurance",
    "the savings account",
    "the green energy add-on",
    "landlord cover",
    "the overdraft facility",
)
TEAMS = (
    "the billing team",
    "customer operations",
    "the claims desk",
    "field services",
    "the complaints team",
    "finance",
    "the compliance team",
    "the onboarding team",
)

SENTENCES = (
    "The meeting opened with a review of actions from {month}, most of which are complete.",
    "{name} confirmed that {team} has cleared the backlog of routine requests.",
    "Customers in {city} reported longer waits on the phone line during the first week of {month}.",
    "The renewal letters for {product} will be sent in two batches to spread the call volume.",
    "Average handling time fell to {mins} minutes after the new knowledge articles went live.",
    "A pilot of paperless statements in {city} reached {pct} per cent uptake within six weeks.",
    "{name} asked whether the welcome pack could be shortened, and the group agreed to try a two-page version.",
    "The supplier has agreed to hold its prices until the end of {month}.",
    "Payments are taken on the first working day of each month unless the customer chooses another date.",
    "Section {sec} sets out how either party may end the agreement with thirty days' written notice.",
    "If a payment is missed, a reminder is sent after seven days and no fee is charged for the first reminder.",
    "The premium for {product} is reviewed once a year and the customer is told of any change in advance.",
    "{team} will publish a revised script for vulnerable customers before the end of {month}.",
    "The maintenance window on {day} runs from two until four in the morning, and no customer impact is expected.",
    "Survey scores for {product} rose by {pct} points compared with the same quarter last year.",
    "{name} will circulate the draft budget to department heads by {day}.",
    "The office in {city} will close at noon on the last Friday of {month} for a staff training session.",
    "Meter readings submitted through the app are now processed within one working day.",
    "Claims under {amount} pounds can be settled without a site visit if photographs are provided.",
    "The policy does not cover gradual wear and tear, which is explained in section {sec}.",
    "A customer may add a named driver at any time, and the change takes effect from the next day.",
    "Refunds are returned to the original payment method within five working days.",
    "{team} raised a question about the wording of the cancellation letter, which will be simplified.",
    "The new hold music was well received, although some customers asked for shorter queue messages.",
    "Energy usage in the {city} depot dropped after the lighting was replaced last {month}.",
    "Training for new advisers now includes a half-day on clear writing.",
    "The next quarterly review is booked for {day} in the {city} office, with a dial-in for remote staff.",
    "Direct debit customers will see the new amount on statements from {month}.",
    "{name} noted that the complaint about delayed letters was resolved once the print run was rescheduled.",
    "The appendix lists the tariff rates for each region, rounded to two decimal places.",
    "There were no data protection incidents reported this quarter.",
    "Feedback from {city} suggests the online form is easier to use since the address lookup was added.",
    "The agreement renews automatically unless the customer tells us otherwise before the renewal date.",
    "{team} is recruiting two additional advisers to cover the busier winter period.",
    "Any excess shown in the schedule is deducted from the settlement amount.",
    "The figures in table {sec} are provisional and will be confirmed after the audit.",
    "Customers can download a copy of their annual statement from the account page at any time.",
    "The emergency helpline remains open around the clock, including bank holidays.",
    "Contractors must sign in at reception and wear a visitor badge while on site.",
    "{name} thanked everyone for their work on the {month} system upgrade, which finished on schedule.",
    "Interest is calculated daily and paid into the account on the anniversary of opening.",
    "Changes to the opening hours of the {city} branch will be posted on the website a month in advance.",
    "The working group recommended keeping the current claims form, with minor wording changes.",
    "Average response time to written complaints is now {mins} days, within the eight-week limit.",
    "Large-print and braille versions of the terms are available on request.",
    "The service level for callbacks is two working days, and {pct} per cent were met last month.",
    "The board approved the proposal to extend weekend opening in {city} for a three-month trial.",
    "Stock of replacement meters is sufficient for the planned installations in {month}.",
    "{team} will review the escalation process and report back at the next meeting.",
    "A summary of the changes will be emailed to all affected customers before {day}.",
)

DAYS = (
    "Monday the 3rd",
    "Tuesday the 11th",
    "Wednesday the 19th",
    "Thursday the 6th",
    "Friday the 24th",
)


def rng_for(seed: str) -> random.Random:
    return random.Random(int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big"))


def _sentence(rng: random.Random) -> str:
    template = rng.choice(SENTENCES)
    return template.format(
        name=rng.choice(NAMES),
        city=rng.choice(CITIES),
        month=rng.choice(MONTHS),
        product=rng.choice(PRODUCTS),
        team=rng.choice(TEAMS),
        day=rng.choice(DAYS),
        mins=rng.randint(4, 12),
        pct=rng.randint(12, 88),
        sec=f"{rng.randint(2, 9)}.{rng.randint(1, 6)}",
        amount=rng.choice(("500", "750", "1,000", "1,500", "2,500")),
    )


def paragraph(rng: random.Random) -> str:
    out: list[str] = []
    while len(out) < rng.randint(3, 6):
        s = _sentence(rng)
        if s not in out:
            out.append(s)
    return " ".join(out)


def paragraphs_for(seed: str, target_tokens: int, joiner: str = "\n\n") -> list[str]:
    """Paragraphs whose joined estimate reaches ``target_tokens`` (shared estimator)."""
    rng = rng_for(seed)
    paras: list[str] = []
    while estimate_tokens(joiner.join(paras)) < target_tokens:
        if rng.random() < 0.18:
            paras.append(
                f"{rng.randint(1, 12)}. {rng.choice(('Background', 'Actions', 'Terms', 'Figures', 'Notes', 'Next steps', 'Summary', 'Scope'))}"
            )
        paras.append(paragraph(rng))
    return paras


def insert_at(paras: list[str], span: str | None, depth: str) -> list[str]:
    """Insert ``span`` as its own paragraph at ``start`` (after the first paragraph),
    ``middle`` or ``end`` (before the last paragraph). ``none`` inserts nothing."""
    if span is None or depth == "none":
        return list(paras)
    n = len(paras)
    index = {"start": 1, "middle": n // 2, "end": max(1, n - 1)}[depth]
    return [*paras[:index], span, *paras[index:]]


def long_text(
    seed: str,
    target_tokens: int,
    *,
    span: str | None = None,
    depth: str = "none",
    head: str = "",
    tail: str = "",
    joiner: str = "\n\n",
    wrap: Callable[[str], str] | None = None,
) -> str:
    """``head`` + filler with ``span`` at ``depth`` + ``tail``, about ``target_tokens`` in all."""
    fixed = estimate_tokens(head + tail + (span or ""))
    paras = insert_at(paragraphs_for(seed, max(50, target_tokens - fixed), joiner), span, depth)
    body = joiner.join(paras)
    if wrap is not None:
        body = wrap(body)
    return head + body + tail
