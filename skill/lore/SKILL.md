---
name: lore
description: Session retrospective — distill this session's learnings into lore (personal + project spaces). Invoke when the user runs /lore, at a natural session end when 5+ knowledge signals accumulated (suggest at 5, recommend strongly at 8), or after a major correction worth capturing. Requires the lore MCP server.
---

# /lore — retrospective knowledge capture

You are distilling THIS session into durable knowledge. The lore binary handles storage, indexing, and sync; your job is judgment: what is worth keeping, what is true, and who it belongs to.

## Step 1 — scan the session for signals

Walk the conversation and collect:

- **Corrections**: the user corrected your approach, a conclusion, or a fact.
- **Failures**: something failed in a way future sessions should not rediscover.
- **Confirmations**: the user explicitly validated a hypothesis or approach.
- **Directives**: "always X", "never Y", stated preferences.
- **Surprises**: outcomes that contradicted a reasonable expectation.
- **Decisions**: choices made, especially quick ones (mark provisional).

Classify each signal: `explored` (tried, inconclusive), `concluded` (evidence supports it), `corrected` (a prior belief was wrong).

## Step 2 — anti-poisoning check (do this before writing anything)

- A conclusion that was **corrected mid-session must not be encoded as knowledge**. Encode the correction, with the marker `[CORRECTED]` and the applicability criteria; if a stored entry holds the old belief, update it to `[DEPRECATED]` pointing at the correction.
- **Never encode comfort as truth.** The user being satisfied is not evidence; the thing working is. User frustration is diagnostic (what went wrong), never directive (what is true).
- Distinguish what was **verified** from what was merely **stated**. Unverified statements enter as `experimental`, never higher.

## Step 3 — route each learning by subject

- **About the user** — preferences, communication style, trust patterns, craft standards, personal ops habits, cross-project patterns → `personal` space. Always.
- **About this codebase** — architecture decisions, constraints, gotchas, corrected conclusions specific to this repo → the current project's space (lore detects it from CWD; if none exists, ask the user whether to create one with `lore project init`).
- **Ambiguous** → `personal`. A later session can copy it to the project space explicitly; the reverse move is forbidden by the binary.

Anything touching the user model (profile, feedback, frustration analysis, trust topology) is personal-only by construction — never suggest sharing it.

## Step 4 — write entries via `lore_put`

Per learning: a clear title, a body that states the principle first and the evidence after, the domain (`layer/name`, e.g. `ops/deploy`, `craft/go-testing`), markers where they apply:

- `[CONTEXT]` — has variants; state which context each variant applies to.
- `[PROVISIONAL]` — decided fast, may reverse.
- `[IMPORTANT]` — user bias to watch for; surface respectfully when triggered.
- `[NON-NEGOTIABLE]` — never compromise, even if asked.
- `[DIRECTIVE]` — origin is a user order, not evidence.
- `[CORRECTED]` / `[DEPRECATED]` — the anti-poisoning pair.

Confidence: new evidence-based entries start `experimental` or `provisional`. Only explicit user confirmation across sessions promotes (`validated`, then `hardened`). If this session contradicts a `validated` entry, that is a **paradigm alarm**: do not silently overwrite — write the correction, mark the old entry `[DEPRECATED]`, and tell the user what changed.

Origin: `evidence` (observed), `directive` (user order), `convention` (team/project norm), `constraint` (external limitation). Record it; when context changes later, origin says which knowledge is ripe for revisiting.

Updating an existing entry beats creating a near-duplicate: `lore_search` first, then `lore_put` with the same domain/title to version it.

## Step 5 — report

One compact summary to the user: N entries written (per space), anything deprecated/corrected, anything you deliberately did NOT capture and why. If a learning looks valuable to a shared space the user belongs to, *suggest* `lore share entry` — never execute it yourself.

## Invocation autonomy (outside this skill)

- Reading (`lore_search`, `lore_get`) mid-task: always autonomous, no permission needed.
- A single clean correction mid-session: one inline `lore_put` (personal, `provisional`), acknowledged in one line — allowed without running the full retrospective.
- The full retrospective: suggest, don't self-invoke, unless the user has set `lore config autocapture auto`.
