# MCP e2e — verified transcript + exact rerun instructions

Phase 2 `lore mcp` was proven end-to-end on 2026-07-08 against Claude Code 2.1.205
(`claude -p` driving the stdio MCP server as a real client). Everything below uses a
scratch `LORE_HOME` — **never** the real `~/.lore` or `~/.claude/distill`.

## Setup (bash; any scratch root works)

```bash
export PATH="$PATH:/c/Program Files/Go/bin"
SCRATCH=/c/tmp/lore-mcp-e2e            # pick any scratch dir OUTSIDE the repo
mkdir -p "$SCRATCH/bin" "$SCRATCH/distill-mirror" "$SCRATCH/proj"

# 1. build a private copy of the binary (repo-root lore.exe may be rebuilt by others)
cd /d/Projects/lore
go build -o "$SCRATCH/bin/lore.exe" ./cmd/lore

# 2. scratch LORE_HOME + identity
export LORE_HOME="$SCRATCH/lorehome"
"$SCRATCH/bin/lore.exe" init --yes-i-saved-it --name mcptest

# 3. CRITICAL: `lore init` defaults config.json distill_dir to the REAL
#    ~/.claude/distill. Repoint it at a scratch mirror BEFORE any MCP write,
#    or personal-space writes will re-render the user's real distill dir.
cat > "$LORE_HOME/config.json" <<EOF
{ "distill_dir": "$SCRATCH/distill-mirror" }
EOF

# 4. seed entries with a distinctive fact
L="$SCRATCH/bin/lore.exe"
"$L" put --domain ops/deploy --title "Deployment procedure" \
  --markers NON-NEGOTIABLE --confidence validated \
  "Deploys go through canary first: every release bakes on the canary fleet for 30 minutes before full rollout. Marker [NON-NEGOTIABLE]."
"$L" put --domain ops/incident --title "Incident channel" --confidence validated \
  "Incidents are coordinated in the #warroom channel, never in DMs."
"$L" put --domain craft/go-testing --title "Table-driven tests" \
  "Prefer table-driven tests with subtests for Go packages."

# 5. scratch MCP project config (forward slashes work fine in JSON on Windows)
cat > "$SCRATCH/proj/.mcp.json" <<EOF
{
  "mcpServers": {
    "lore": {
      "command": "$SCRATCH/bin/lore.exe",
      "args": ["mcp"],
      "env": { "LORE_HOME": "$SCRATCH/lorehome" }
    }
  }
}
EOF
```

## Test 1 — read path (lore_search via a real MCP client)

```bash
cd "$SCRATCH/proj"
claude -p "Use the lore_search tool to find our deployment procedure and quote it exactly." \
  --mcp-config .mcp.json --strict-mcp-config \
  --allowedTools "mcp__lore__lore_search" "mcp__lore__lore_get"
```

Assert: output quotes the seeded fact verbatim. Verified answer (2026-07-08):

> Found it. The deployment procedure is stored in your personal lore space under
> `ops/deploy` (entry `aeb74d74`, validated, marked **[NON-NEGOTIABLE]**). Quoted exactly:
> > Deploys go through canary first: every release bakes on the canary fleet for
> > 30 minutes before full rollout. Marker [NON-NEGOTIABLE].

## Test 2 — write path (lore_put), verified out-of-band via the CLI

```bash
cd "$SCRATCH/proj"
claude -p "Store this learning in lore via the lore_put tool: title 'Rollback window', domain ops/deploy, body 'Rollbacks must happen within 15 minutes of a bad canary signal; after that, roll forward.' Use confidence provisional. Then tell me the entry id it returned." \
  --mcp-config .mcp.json --strict-mcp-config \
  --allowedTools "mcp__lore__lore_put"

# verify the row actually exists in the store
LORE_HOME="$SCRATCH/lorehome" "$SCRATCH/bin/lore.exe" search rollback
LORE_HOME="$SCRATCH/lorehome" "$SCRATCH/bin/lore.exe" get <entry-id-from-answer>
```

Verified answer (2026-07-08):

> Stored. The entry id is `4c572230-2346-4c79-b9d0-db2a8ab7548e` (v1), saved in the
> "personal" space under domain ops/deploy with confidence provisional.

`lore search rollback` then found the row (`Rollback window (provisional)`), and
`lore get <id>` printed the full body — the MCP write landed in SQLite for real.

Side effects verified: the personal-space write re-rendered the **scratch** distill
mirror (`$SCRATCH/distill-mirror/SPINE.md`, `ops/deploy.md`, `ops/incident.md`,
`craft/go-testing.md` all present). Daemon poke is covered by unit test
`TestAfterWriteSideEffects` (internal/mcpserver) with a fake `/admin/sync` server.

## Notes / gotchas

- Flags: `--mcp-config .mcp.json --strict-mcp-config` are required in headless
  `claude -p`; project `.mcp.json` alone is not trusted without approval. Tool names
  are `mcp__lore__<tool>`; pass each to `--allowedTools` (space-separated args work).
- Timeout generously (120s+); each `claude -p` run takes ~15-45s.
- The MCP server only re-renders distill when `config.json` **explicitly** sets
  `distill_dir` (it never assumes `~/.claude/distill` on its own) and only when the
  write touched the personal space — but `lore init` writes the real default into
  config.json, hence step 3 above is mandatory in every scratch setup.
- Unit tests: `go test ./internal/mcpserver/` (handlers driven directly against a
  temp LORE_HOME; search scoping/filtering, put routing incl. subject=codebase via a
  fake `.git/config`, share confirm flow + user-model refusal, daemon poke +
  distill re-render).
