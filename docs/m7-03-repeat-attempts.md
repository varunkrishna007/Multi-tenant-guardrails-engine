# M7-03 · Repeat-attempt counting (as built)

A model's answer varies a little from call to call. A sender whose content scores near a block
threshold could resubmit it until one draw falls under, and the content would pass. The Guard
Service now counts, per tenant, the checks that **blocked** a piece of content. Once the same
content has been blocked twice within 15 minutes, a further submission of it is refused
deterministically: no redaction, no model call, no provider call.

Code: `guard/repeat.py` (the counting, the store port and its in-process store); three narrow hooks
in `guard/service.py` (the refusal, the count, the construction); settings under `guard`.

## The rule

| | |
|---|---|
| Where | `input` only (`guard.repeat_guard_points`). It is where a sender resubmits. At `plan`, `tool_call`, `tool_result` and `output` the content comes from the agent or its tools, and a tenant-wide key would turn one flaky block of templated content into minutes of refusals for everyone. Other points can be named later. |
| Threshold | 2 counted blocks of the same content (`guard.repeat_threshold`; 0 turns it off). The first retry still gets a fresh model call (the first block may have been a close call, or the sender may honestly resend); the third try does not. |
| Window | 900 s (`guard.repeat_window_s`), sliding: each block counts for 900 s from when it happened. |
| Settings | Platform settings only. A tenant can't change or switch them off. |
| The refusal | decision `block`, reason `deterministic`, rule `repeat_attempt` (a new deterministic kind, layer `floor`, `count` = the counted blocks in the window), `model_called` false. A short engine-authored detail ("this content was blocked 2 times in the last 15 minutes"). It runs after the other deterministic checks (so a real deny-pattern hit is reported as itself) and before redaction and the model call. |

## What "the same content" is

The key is `(tenant, guard point, tool, repeat key, bundle hash)`.

* The **repeat key** is the SHA-256 of the content **normalised**: NFKC, format and zero-width
  characters removed, case-folded, runs of whitespace collapsed. It is taken on the content as
  submitted. A changed space, capital, full-width letter or zero-width character does not make it
  new. The key is held only in memory and never put in a record or a log; the audit record's
  `content_sha256` is the raw hash, as before.
* The **bundle hash** is that of the policy that decides the check (the active version, or an
  enforce candidate's own). A published fix starts a clean count, and a canary's blocks count only
  under the canary's hash.
* It is **not per conversation.** `conversation_id` is chosen by the caller (it is a rollout
  control, not a security boundary) and a verified context carries only the tenant and an expiry,
  so there is no subject to key on; a sender could otherwise change the id on every try.
* It is **per tenant**: the key starts with the tenant id, and each tenant has its own bound on the
  keys it may hold, so one tenant's traffic can't push another's counts out.

## What counts as a block

A final verdict whose decision is `block` and whose reason is `policy` (the model answered and the
rules blocked) or `provider_safety` (the provider refused the content, so the refusal is not sent
again). Not counted: `model_failure`, `policy_unavailable`, capacity refusals,
`content_too_large`, `invalid_request`, forbidden checks (none of them says anything about the
content), and the deterministic blocks (they are free and repeat on their own). An escalation is
not a block. A shadow candidate's decision is not the verdict and is not counted; an enforce
candidate's is.

**The refusal itself is not counted and does not extend the window.** A sender can't keep a text
blocked by resubmitting it: when the counted blocks have aged out, the next submission goes to the
model again.

## Concurrent copies (single flight)

Copies of one content sent at the same moment would all read the count before any block was
noted, and all go to the model: every one a fresh draw. So while a slot has no allowing outcome in
the window, **one** model call per slot is in flight and the other copies wait for it, within the
check's own time (the guard point's budget cap, less what the check has used). Then each reads the
count again: if the call blocked and the count reached the threshold, all are refused; if it
blocked below the threshold, one more goes and the rest wait again; if it failed, one goes. Once a
call on the slot **allows** the content, the slot is open for the window and nothing waits, so
many users sending "hi" don't queue behind each other. An **escalation does not open it**:
content that escalates on some draws and blocks on others goes one call at a time, and its blocks
count (the cost: benign escalate-band duplicates wait for each other).

**The count always comes first.** At the threshold a copy is refused whatever the open state; an
open slot only spares the wait. A block noted on an open slot closes it again, so after an allow
the next blocks go back through single flight, and a sender can't use one lucky allow to switch
the refusal off for the window.

A copy that waited calls the gateway with only what is left of the guard point's cap, so the wait
and its own call together stay within the cap (plus the gateway's cancellation grace). A copy
whose time runs out while waiting takes the guard point's existing timeout outcome (a
`model_failure`, failure kind `timeout`, no call of its own); there is no new failure. The table of calls in flight holds
one entry per slot being decided, as many as there are checks in flight. A store that fails means
no waiting and no refusal.

## Shadow candidates

When the active side refuses a repeat, the shadow candidate's model call is not made either, and
the check is not one of the comparisons the agreement figures count; the audit record's
`candidate_reason` is `repeat_refusal`.

## The store

`RepeatAttemptStore` (async: `blocked(slot, now)`, `note_block(slot, now)`) is the port. The
in-process `InMemoryRepeatAttempts` holds at most 10,000 slots per tenant and 200,000 overall,
oldest first; over the overall bound the tenant holding the most slots pays, and among tenants
holding equally many, the one that added a slot most recently (the one pushing the total over). A store that fails
never changes a verdict: the check goes on to the model as it did before this feature.

## Residuals (stated, not fixed)

* **Rewording evades it.** It is a hash of the (normalised) text, not a judgement of meaning. A
  paraphrase is new content. This is not a defence against an adaptive attacker; it removes the
  cheapest attack, resubmitting the same text until a draw is lucky.
* **It counts per replica.** The in-process store is not shared, so n replicas give a sender up to
  n times the tries, and a restart forgets the counts. With the guard as its own service (M7-10)
  the runtime replicas share one service's counts; sharing them across service replicas is
  deferred (M7-10 step 5), and would replace the store behind the same port.
* **Look-alike letters evade it.** A Cyrillic `а` for a Latin `a`, or any other confusable, is
  new content; only characters that draw nothing are ignored.
* **A tenant can wipe its own counters.** Any user of the tenant can push a slot out of the
  tenant's 10,000 with 10,000 distinct contents that the model blocks within the window (each
  costs a model call).
* **Within a tenant the refusal is a membership oracle.** "This content was blocked N times" tells
  another end user that someone sent that exact text recently. That is the cost of the
  tenant-wide key, seen from the other side.
* **`conversation_id` is not a boundary**, which is why the key ignores it. The cost: the same
  text from different end users of one tenant counts together. A text blocked twice for one user
  is refused for the next user who sends the identical text, for the rest of the window.
* **The open table is shared across tenants** (bounded at 200,000 slots). One tenant's distinct
  allowed contents can push out another's open entries; that tenant's first-time duplicates then
  wait for each other again. It costs latency, never a refusal or a pass.
* **Only `input`** by default.
* A first block may itself have been a close call or a wrong call; the counted blocks are not
  reviewed.
