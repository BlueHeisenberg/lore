package distill

import (
	"strings"
	"testing"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// A curated SPINE survives patching verbatim: custom headers and "when to
// read" phrasing kept, dead pointers dropped, new entries appended under the
// section whose header mentions their layer.
func TestPatchSpinePreservesCuration(t *testing.T) {
	curated := `# Distill Knowledge Index

<!-- managed comment -->

## Feedback / preferences
- [Risk transparency](feedback/risk_transparency.md) — before destructive changes; substance over reassurance [NON-NEGOTIABLE]

## Projects — homelab (custom header)
- [Deployment state (LIVE)](projects/deploy_state.md) — assume it's up [staleness 90d]
- [Old thing](projects/gone.md) — this entry was deleted
`
	entries := []store.Entry{
		{Domain: "feedback/risk_transparency", Title: "ignored-title", Body: "ignored body"},
		{Domain: "projects/deploy_state", Title: "ignored", Body: "ignored"},
		{Domain: "projects/new_thing", Title: "New thing", Body: "First line desc."},
		{Domain: "ops/fresh_layer", Title: "Fresh ops", Body: "Ops desc."},
	}
	got := string(patchSpine([]byte(curated), entries))

	for _, want := range []string{
		"# Distill Knowledge Index",
		"<!-- managed comment -->",
		"## Feedback / preferences",
		"substance over reassurance [NON-NEGOTIABLE]", // curated phrasing intact
		"## Projects — homelab (custom header)",       // custom header intact
		"assume it's up [staleness 90d]",
		"- [New thing](projects/new_thing.md) — First line desc.", // appended
		"## ops", // new layer section created
		"- [Fresh ops](ops/fresh_layer.md) — Ops desc.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("patched SPINE missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "gone.md") {
		t.Fatalf("deleted entry's pointer survived:\n%s", got)
	}
	// New project entry must sit inside the custom projects section, not at EOF.
	if strings.Index(got, "new_thing.md") > strings.Index(got, "## ops") {
		t.Fatalf("new project entry landed outside its section:\n%s", got)
	}
	// Idempotence: patching again changes nothing.
	if again := string(patchSpine([]byte(got), entries)); again != got {
		t.Fatalf("patch not idempotent:\n--- first\n%s\n--- second\n%s", got, again)
	}
}
