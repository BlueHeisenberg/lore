package vault

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// testKDF keeps Argon2 cheap in tests (the header records the params, so
// Open needs no knob).
var testKDF = KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

func TestKeyboxRoundtrip(t *testing.T) {
	plain := []byte(`{"hello":"lore"}`)
	env, err := Seal(plain, "pass phrase", "ABCD-EFGH", testKDF)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(env, "pass phrase", "ABCD-EFGH")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip = %q, want %q", got, plain)
	}

	// recovery-code normalization: separators/case/Crockford aliases fold
	if _, err := Open(env, "pass phrase", "abcdefgh"); err != nil {
		t.Errorf("normalized recovery code should open: %v", err)
	}

	if _, err := Open(env, "wrong", "ABCD-EFGH"); err == nil {
		t.Error("wrong passphrase must fail")
	}
	if _, err := Open(env, "pass phrase", "XXXX-XXXX"); err == nil {
		t.Error("wrong recovery code must fail")
	}

	// tamper detection
	env2, err := Seal(plain, "p", "r", testKDF)
	if err != nil {
		t.Fatal(err)
	}
	env2[len(env2)/2] ^= 1
	if _, err := Open(env2, "p", "r"); err == nil {
		t.Error("tampered envelope must fail to open")
	}
}

func initHome(t *testing.T, home, deviceName string) (*store.Store, *keys.Account) {
	t.Helper()
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.GenerateDevice(deviceName, account)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAccount(home, account); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveDevice(home, device); err != nil {
		t.Fatal(err)
	}
	priv, err := device.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, account
}

func TestBackupRestoreRoundtrip(t *testing.T) {
	homeA := t.TempDir()
	st, account := initHome(t, homeA, "origin")
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	e1, err := st.PutEntry(store.PutParams{
		SpaceID: sp.SpaceID, Domain: "ops/deploy", Title: "Deploys",
		Body: "always deploy on tuesdays", Markers: []string{"[IMPORTANT]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := st.PutEntry(store.PutParams{
		SpaceID: sp.SpaceID, Domain: "craft/go", Title: "Go style", Body: "no cgo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEntry(e2.EntryID); err != nil {
		t.Fatal(err)
	}

	env, err := Backup(homeA, "pw", "AAAA-BBBB", testKDF)
	if err != nil {
		t.Fatal(err)
	}

	homeB := t.TempDir()
	if err := Restore(homeB, env, "pw", "AAAA-BBBB", "fresh"); err != nil {
		t.Fatal(err)
	}

	// account restored verbatim
	acctB, err := keys.LoadAccount(homeB)
	if err != nil {
		t.Fatal(err)
	}
	if acctB.AccountID() != account.AccountID() {
		t.Error("restored account id differs")
	}
	// new device, certified by the restored account
	devB, err := keys.LoadDevice(homeB)
	if err != nil {
		t.Fatal(err)
	}
	if err := devB.Cert.VerifyForAccount(account.AccountID()); err != nil {
		t.Errorf("restored device cert: %v", err)
	}

	// store rows: same space id + key, live entry present, tombstone kept
	db, err := syncproto.OpenDB(filepath.Join(homeB, "lore.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, err := syncproto.ListSpaceRecords(db)
	if err != nil || len(recs) != 1 {
		t.Fatalf("restored spaces = %v (err %v)", recs, err)
	}
	if recs[0].SpaceID != sp.SpaceID || !bytes.Equal(recs[0].SpaceKey, key) {
		t.Error("restored space must keep original id and key")
	}
	stB, err := store.Open(filepath.Join(homeB, "lore.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stB.Close()
	got, err := stB.GetEntry(e1.EntryID)
	if err != nil {
		t.Fatalf("restored entry: %v", err)
	}
	if got.Body != e1.Body || got.Signature != e1.Signature {
		t.Error("restored entry must be byte-identical (incl. signature)")
	}
	tomb, err := stB.GetEntry(e2.EntryID)
	if err != nil || !tomb.Tombstone {
		t.Errorf("tombstone must survive restore (err %v, tomb %v)", err, tomb.Tombstone)
	}

	// refuse restoring over an existing home
	if err := Restore(homeA, env, "pw", "AAAA-BBBB", "x"); err == nil {
		t.Error("restore over existing account must refuse")
	}
}
