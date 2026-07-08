# lore — knowledge capture and the distill heritage

How lore relates to [aura-distill](https://github.com/tomacco/aura-distill), what it keeps, and where it deliberately diverges. Read ARCHITECTURE.md first.

## What aura-distill is

A pure prompt-level system — no code, no binary. Markdown instructions plus a data directory:

- **Capture**: the `/distill` skill, a ~770-line process document instructing the model to run a session retrospective: scan for signals (failures, corrections, confirmations, surprises), classify them (`explored` / `concluded` / `corrected`), encode learnings as markdown.
- **Epistemics** (the valuable invention):
  - *Anti-poisoning*: a conclusion corrected mid-session is encoded `[DEPRECATED]`, its correction `[CORRECTED]` with applicability criteria — wrong framings never become durable patterns.
  - *Confidence lifecycle*: `experimental → provisional → validated → hardened`, promoted on user confirmation, demoted on correction. Correcting a `validated` entry is a "paradigm alarm".
  - *Origin tracking*: `evidence | directive | convention | constraint` — when context changes, origin says which decisions are ripe for revisiting.
  - *Markers*: `[CONTEXT]` `[UPDATED]` `[PROVISIONAL]` `[IMPORTANT]` `[NON-NEGOTIABLE]` `[DIRECTIVE]` `[CORRECTED]` `[DEPRECATED]`.
  - *Integrity principles*: anti-sycophancy — never encode comfort as truth; frustration is diagnostic, not directive.
- **Storage**: three tiers. `SPINE.md` index (max 80 lines, one-line pointers with "when to read this"), tier-2 domain files (max ~60 lines, frontmatter with staleness thresholds) across five layers — `craft/ ops/ projects/ profile/ feedback/` — plus an archive tier.
- **Retrieval**: convention only — read SPINE at session start, read the relevant tier-2 file before the first action in a domain. No search.
- **Mechanics**: locking via a `.status` file, checkpoints, spine health checks, compaction thresholds — all enforced only by the model obeying instructions.

## The division of labor in lore

**The LLM keeps the judgment; the lore binary takes the mechanics.**

| Concern | aura-distill | lore |
|---|---|---|
| Signal detection, anti-poisoning classification, user-model inference | LLM (skill) | LLM (skill) — unchanged, this is judgment |
| Markers / confidence / origin / staleness | prose conventions | typed schema fields, enforced by the binary |
| SPINE index | hand-maintained file, dangling pointers possible | rendered view generated from the DB; budget enforced by the renderer; corruption impossible |
| Line budgets, locking, compaction | instructions + `.status` file | code |
| Retrieval | index-scan + model discipline | `lore_search` (FTS5 + filters: domain, marker, confidence, space); tiered priming remains the default context strategy |
| Concurrency | single machine, single writer | multi-device sync (version vectors), multi-author spaces |

Enforcement examples the binary makes possible: reject applying a `[DEPRECATED]` entry, auto-flag entries past staleness, require a `[CORRECTED]` chain when overwriting a `validated` entry (the paradigm alarm as a real check).

## The skill: `/lore`

One user-invocable skill, named `/lore`, whose default action is the retrospective capture (the `/distill` equivalent). Retrieval has no slash command — the agent uses the MCP tools mid-task. `/distill` and `/lore` coexist during migration: the directory adapter mirrors the `personal` space to `~/.claude/distill/`, so either system sees the other's knowledge until `/distill` is retired.

### Invocation policy (skills are model-invocable)

A skill is a tool: the model can invoke it autonomously when its description matches the situation. lore makes the trigger policy explicit and tiered:

1. **Always autonomous — reads.** `lore_search` / `lore_get` mid-task need no permission; retrieval is just context.
2. **Autonomous with a light touch — single-fact capture.** A clean, isolated correction ("no, we deploy through canary first") may be captured inline via one `lore_put` as `provisional`, acknowledged to the user in one line. Cheap and reversible (entries are versioned).
3. **Suggest by default — full retrospective.** The memory-pressure heuristic stays (count signals; at ~5 suggest `/lore`, at ~8 recommend strongly). `lore config autocapture suggest|auto` lets a user opt into automatic end-of-session capture.

Safety properties that make autonomous writes acceptable:
- Autonomous writes land in the `personal` space only, as `experimental`/`provisional`. Never a shared space, never a confidence promotion — only user-confirmed patterns climb the ladder.
- Every entry is versioned and signed; anything can be reverted.

## Capture routing (two features, one retrospective)

The `/lore` retrospective classifies every learning by *subject* and routes it:

- **About the user** (profile, feedback, craft standards, personal ops habits, cross-project patterns) → **personal lore**. Always.
- **About the codebase** (architecture decisions, project constraints, gotchas, corrected conclusions specific to this repo) → the **current project's lore** (space detected from CWD; created on first capture via `lore project init` prompt if missing).
- **Ambiguous** → personal (the safe side; a later capture can promote it to the project space explicitly — the reverse move is what the binary forbids).

This replaces distill's flat five-layer directory with a subject split: `profile/` and `feedback/` layers only ever exist in personal lore; `projects/` content lives in project spaces; `craft/` and `ops/` route by subject (your habits → personal; this repo's deploy procedure → project).

## Sharing-aware epistemics (what distill never needed)

- **Personal lore is non-shareable by construction.** The user model — trust patterns, delegation habits, frustration analysis — never leaves your account's devices; the binary refuses to add members to the personal space or move its entries into a project space. No mis-click can sync your user model to a collaborator.
- **Cross-author contradictions are knowledge states, not sync conflicts.** When two authors' entries in the same domain disagree, LWW must not squash them: lore detects the contradiction and surfaces it as a `[CONTEXT]` candidate ("which context applies?") — distill's conflict-detection idea generalized to teams.
- **Confidence is observer-relative at read time.** A teammate's `validated` arrives as your `provisional` until it survives your own sessions. Authorship is signed, so provenance is always available to the reader.

## License note

Reimplementing the concepts and staying format-compatible is clean-room work. The aura-distill process document itself is authored work — before shipping any derived skill text inside lore, check the repo license or ask the author.
