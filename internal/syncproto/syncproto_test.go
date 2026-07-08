package syncproto

import (
	"testing"
)

func TestVVMerge(t *testing.T) {
	a := VV{"d1": 3, "d2": 7}
	b := VV{"d2": 5, "d3": 2}
	got := a.Merge(b)
	want := VV{"d1": 3, "d2": 7, "d3": 2}
	if len(got) != len(want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("merge[%s] = %d, want %d", k, got[k], n)
		}
	}
	// inputs untouched
	if a["d3"] != 0 || b["d2"] != 5 {
		t.Errorf("merge mutated inputs: a=%v b=%v", a, b)
	}
	// merge with nil/empty
	if m := (VV{}).Merge(a); m["d2"] != 7 {
		t.Errorf("empty.Merge = %v", m)
	}
	if m := a.Merge(nil); m["d1"] != 3 {
		t.Errorf("merge nil = %v", m)
	}
}

func TestVVCoversAndSince(t *testing.T) {
	local := VV{"d1": 5, "d2": 2}
	if !local.Covers(VV{"d1": 5}) {
		t.Error("covers subset failed")
	}
	if !local.Covers(nil) {
		t.Error("covers nil failed")
	}
	if local.Covers(VV{"d1": 6}) {
		t.Error("covers should fail on higher seq")
	}
	if local.Covers(VV{"d9": 1}) {
		t.Error("covers should fail on unknown device")
	}

	// Since = "the holder of this vv is missing (device, seq)".
	if local.Since("d1", 5) {
		t.Error("seq 5 from d1 is covered")
	}
	if !local.Since("d1", 6) {
		t.Error("seq 6 from d1 is missing")
	}
	if !local.Since("d9", 1) {
		t.Error("any seq from unknown device is missing")
	}
}

func TestVVDiffMath(t *testing.T) {
	// A has d1..5, d2..2; B has d1..3, d2..4. After exchanging vvs,
	// A sends d1:{4,5}, B sends d2:{3,4}; both converge to d1:5,d2:4.
	a := VV{"d1": 5, "d2": 2}
	b := VV{"d1": 3, "d2": 4}
	var aSends, bSends []int64
	for seq := int64(1); seq <= 5; seq++ {
		if b.Since("d1", seq) && seq <= a["d1"] {
			aSends = append(aSends, seq)
		}
		if a.Since("d2", seq) && seq <= b["d2"] {
			bSends = append(bSends, seq)
		}
	}
	if len(aSends) != 2 || aSends[0] != 4 || aSends[1] != 5 {
		t.Errorf("A sends %v, want [4 5]", aSends)
	}
	if len(bSends) != 2 || bSends[0] != 3 || bSends[1] != 4 {
		t.Errorf("B sends %v, want [3 4]", bSends)
	}
	merged := a.Merge(b)
	if merged["d1"] != 5 || merged["d2"] != 4 {
		t.Errorf("converged vv = %v", merged)
	}
	if !merged.Covers(a) || !merged.Covers(b) {
		t.Error("merged must cover both inputs")
	}
}

func TestBlindSpaceIDDeterminism(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	id := "8f14e45f-ceea-467f-a34e-cbf3a2b62f11"

	b1 := BlindSpaceID(key, id)
	b2 := BlindSpaceID(key, id)
	if b1 != b2 {
		t.Fatalf("blinding not deterministic: %s != %s", b1, b2)
	}
	if len(b1) != 64 { // hex SHA-256
		t.Fatalf("blinded id length = %d, want 64", len(b1))
	}
	if BlindSpaceID(key, "other-space") == b1 {
		t.Error("different space ids must blind differently")
	}
	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 1
	if BlindSpaceID(key2, id) == b1 {
		t.Error("different keys must blind differently")
	}
	// pinned test vector so the wire format cannot silently drift
	zero := make([]byte, 32)
	const want = "b638b0d97aa8ae094465774f431f5ca1db9b670206f874c8cb22bb3120d53e54"
	if got := BlindSpaceID(zero, "s"); got != want {
		t.Fatalf("test vector drifted: got %s, want %s", got, want)
	}
}
