package invite

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestWordlistIntegrity(t *testing.T) {
	if len(wordlist) != 2048 {
		t.Fatalf("wordlist has %d words, want 2048", len(wordlist))
	}
	re := regexp.MustCompile(`^[a-z]+$`)
	seen := map[string]bool{}
	prefixes := map[string]bool{}
	for i, w := range wordlist {
		if !re.MatchString(w) {
			t.Fatalf("word %d %q is not lowercase a-z", i, w)
		}
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
		p := w
		if len(p) > 4 {
			p = p[:4]
		}
		if prefixes[p] {
			t.Fatalf("duplicate 4-letter prefix %q (word %q)", p, w)
		}
		prefixes[p] = true
	}
	// Spot-check the BIP39 anchors.
	if wordlist[0] != "abandon" || wordlist[2047] != "zoo" {
		t.Fatalf("wordlist anchors wrong: first=%q last=%q", wordlist[0], wordlist[2047])
	}
}

func TestTokenRoundtripAndNormalization(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	s := tok.String()
	// Canonical form: word-word-word-word-NN.
	if !regexp.MustCompile(`^[a-z]+-[a-z]+-[a-z]+-[a-z]+-\d{2}$`).MatchString(s) {
		t.Fatalf("canonical form %q", s)
	}
	for _, variant := range []string{
		s,
		strings.ToUpper(s),
		strings.ReplaceAll(s, "-", " "),
		"  " + strings.ReplaceAll(s, "-", "  \t") + " \n",
	} {
		got, err := ParseToken(variant)
		if err != nil {
			t.Fatalf("ParseToken(%q): %v", variant, err)
		}
		if got.String() != s {
			t.Fatalf("ParseToken(%q) = %q, want %q", variant, got.String(), s)
		}
	}
	// 4-letter prefixes decode too.
	parts := strings.Split(s, "-")
	for i := 0; i < 4; i++ {
		if len(parts[i]) > 4 {
			parts[i] = parts[i][:4]
		}
	}
	got, err := ParseToken(strings.Join(parts, "-"))
	if err != nil || got.String() != s {
		t.Fatalf("prefix decode = %q, %v; want %q", got.String(), err, s)
	}
	// Single-digit number equals its zero-padded form.
	one, err := ParseToken("abandon-ability-able-about-7")
	if err != nil {
		t.Fatal(err)
	}
	two, err := ParseToken("abandon-ability-able-about-07")
	if err != nil {
		t.Fatal(err)
	}
	if one.String() != two.String() {
		t.Fatalf("7 vs 07 mismatch: %q %q", one.String(), two.String())
	}
}

func TestParseTokenRejects(t *testing.T) {
	for _, bad := range []string{
		"",
		"ABCD1234",                                // LAN invite code shape
		"maple-rocket-sunset-73",                  // three words
		"maple-rocket-sunset-cactus-word",         // no number
		"maple-rocket-sunset-cactus-100",          // number out of range
		"maple-rocket-sunset-cactus-73-extra",     // trailing junk
		"xxxxzzzz-rocket-sunset-cactus-73",        // unknown word
		"maple rocket sunset cactus seventythree", // word number
	} {
		if _, err := ParseToken(bad); err == nil {
			t.Fatalf("ParseToken(%q) unexpectedly succeeded", bad)
		}
	}
	if IsToken("ABCD1234") {
		t.Fatal("LAN code must not be detected as a token")
	}
	if !IsToken("abandon zoo zebra able 42") {
		t.Fatal("valid token not detected")
	}
}

func TestAddrShape(t *testing.T) {
	tok, err := ParseToken("abandon-ability-able-about-00")
	if err != nil {
		t.Fatal(err)
	}
	addr := tok.Addr()
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(addr) {
		t.Fatalf("addr %q not 32 hex chars", addr)
	}
	// Deterministic and distinct from another token's address.
	if tok.Addr() != addr {
		t.Fatal("addr not deterministic")
	}
	other, _ := ParseToken("abandon-ability-able-about-01")
	if other.Addr() == addr {
		t.Fatal("distinct tokens share an address")
	}
}

func TestPayloadRoundtripAndTamper(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		SpaceID: "space-1", SpaceKey: bytes.Repeat([]byte{7}, 32),
		Kind: "shared", Name: "team", ProjectRef: "ref", Role: "writer",
		OwnerAccount: "aa", OwnerEncPub: "bb",
	}
	blob, err := SealPayload(tok, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPayload(tok, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.SpaceID != p.SpaceID || !bytes.Equal(got.SpaceKey, p.SpaceKey) ||
		got.Role != p.Role || got.Name != p.Name || got.OwnerEncPub != p.OwnerEncPub {
		t.Fatalf("payload roundtrip: %+v", got)
	}
	// One flipped bit fails the AEAD.
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)/2] ^= 1
	if _, err := OpenPayload(tok, tampered); !errors.Is(err, ErrBlobCorrupt) {
		t.Fatalf("tampered payload: %v", err)
	}
	// Wrong token fails.
	other, _ := NewToken()
	if other.String() != tok.String() {
		if _, err := OpenPayload(other, blob); !errors.Is(err, ErrBlobCorrupt) {
			t.Fatalf("wrong-token open: %v", err)
		}
	}
	// A payload blob cannot be opened as a claim (AAD separation).
	if _, err := OpenClaim(tok, blob); !errors.Is(err, ErrBlobCorrupt) {
		t.Fatalf("payload-as-claim: %v", err)
	}
}

func TestClaimRoundtripMACAndTamper(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClaim(tok, "acct-pub", "enc-pub", "enc-sig", "laptop")
	blob, err := SealClaim(tok, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenClaim(tok, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountPub != c.AccountPub || got.EncPub != c.EncPub ||
		got.EncPubSig != c.EncPubSig || got.Name != c.Name {
		t.Fatalf("claim roundtrip: %+v", got)
	}
	// MAC bound to the account key: swapping the account fails Verify.
	swapped := got
	swapped.AccountPub = "someone-else"
	if err := swapped.Verify(tok); err == nil {
		t.Fatal("claim MAC must bind the account pubkey")
	}
	// Tampered ciphertext fails.
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenClaim(tok, tampered); !errors.Is(err, ErrBlobCorrupt) {
		t.Fatalf("tampered claim: %v", err)
	}
}
