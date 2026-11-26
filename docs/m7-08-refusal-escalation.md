# M7-08 · A provider refusal goes to a person where a rule may only escalate (as built)

PF-12 made a provider safety refusal always a block. Some rules exist to put content in front of
a person, never to refuse it. Content the provider refuses to judge is the kind of content such
a rule is for. So at a guard point with such a rule, the refusal now **escalates**.

## Where it applies

Five shipped packs have an enforce rule that may only escalate (any tenant extending the pack
has it):

| Pack | Rule | Guard points |
|---|---|---|
| healthcare | emergency symptoms | `input` |
| responsible AI | self-harm risk, vulnerability | `input` |
| energy | safety report | `input` |
| finance | scam signal | `input` |
| insurance | fraud signal | `input` and `tool_result` |

At `tool_result` (insurance only) a provider-refused **third-party tool result** goes to a
person; the content is withheld either way. That follows from the rule below (any guard point
whose evaluated set has such a rule), and it is the one case where the refused text did not come
from the end user. The floor and the other packs have no escalate-only rule, so `plan`,
`tool_call` and `output` always block.

**Production checks only.** The refusal is escalated, and takes from the cap, only on the
production check path. A draft test in the Admin API, calibration, the evidence and publish
gates, tool screening and a shadow candidate's evaluation all keep a refusal as a block, take
nothing from the cap and route nothing, so an admin run of refused examples can't use up the
tenant's production cap.

## The rule

A provider safety refusal on a **deciding** call becomes decision `escalate`, reason
`provider_safety` (the cause stays visible; the refusal's code is kept as `failure_reason`),
instead of `block`, when **all** of these hold:

1. The guard point's evaluated rule set contains at least one **enforce**-mode rule whose
   `max_action` is `escalate`. Shadow rules never act, so they don't count. A `skip_model` tool
   evaluates the floor only, so it stays a block. It is per guard point, not per rule: a refusal
   says nothing about which rule the content would have matched.
2. The engine can route an escalation (an escalation router is attached). Otherwise nobody would
   see it, and it stays a block (fails closed).
3. The tenant's **cap** isn't spent (below).

Nothing is configurable per tenant. Everything deterministic before the model (deny patterns, the
secret formats, the size limit, the tool allow-list, repeat refusals) still blocks, and so does
every refusal at a guard point with no escalate-only rule. A shadow candidate's refusal is still
only logged.

**The cost, stated plainly.** The floor's rules (injection, secrets, cross-tenant probes) block and
cover every guard point, so a rule set "of escalate-only rules alone" never exists. At a guard
point with an escalate-only rule, **a refused jailbreak goes to a person instead of being
blocked.** It is held either way: `escalate` withholds the content as `block` does, and the caller
must not proceed.

## The cap

`guard.refusal_escalation_cap` (default 20) per tenant and guard point within
`guard.refusal_escalation_window_s` (default 900). **These values are provisional**: nothing has
calibrated them against real traffic. Without a cap, a sender who varies refused texts (the repeat
counter of M7-03 only stops the same text) could flood a person's queue. Past the cap a refusal is a
**block**, exactly as before M7-08, and one alert `refusal_escalations_capped` (a warning) is raised
per tenant per window. 0 turns the feature off.

The counter is in memory behind a port (`RefusalCapStore`) and bounded (50,000 tenant and guard
point pairs, oldest first); per replica, lost on restart, like the repeat store. **A store that
fails means block, never escalate.**

## What a reviewer sees

The item is routed like any escalation (queue, or webhook per the tenant's target), with the
post-redaction content as class D where the tenant's settings hold it. Nothing fired and the
provider gave no score, so `rules` is empty and the item carries **`candidate_rules`**: the keys
of the escalate-only rules at that guard point (what the content might have been about). The
API view and the webhook notice show it. The verdict's `fired` stays empty, and the provider's own
refusal text is nowhere in the item, the verdict or the audit record. Migration 055 adds the
column (`candidate_rules jsonb`) and keeps it immutable like the rest of the item.

If routing fails (the store errors, the queue is full, the router is closing) the existing path
applies: the verdict is still `escalate`, so the content is held back by the caller, the item is
dropped and counted, and an `escalation_dropped` alert is raised, a page, because no reviewer
will see it.

## With repeat counting (M7-03)

A provider refusal is counted by the repeat counter whether it ended as a block or an escalation:
the provider has seen the text and refused it, and it shouldn't be sent again. The first two
submissions of a text escalate; the third gets the deterministic repeat refusal (a block, no
provider call).

## Residuals

* At a guard point with an escalate-only rule, a refused jailbreak reaches a person (above).
* The cap is per replica and provisional; a deployment with several replicas allows up to that many
  times the cap.
* An escalated refusal is a human's work item that may be abuse: the cap bounds the volume, not the
  content.
