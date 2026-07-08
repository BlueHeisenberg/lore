package keys

import (
	"regexp"
	"strings"
	"testing"
)

func TestAccountRoundtrip(t *testing.T) {
	dir := t.TempDir()
	a, err := GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyEncPub(); err != nil {
		t.Fatalf("fresh account enc_pub_sig: %v", err)
	}
	if err := SaveAccount(dir, a); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAccount(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *a {
		t.Fatalf("loaded account differs:\n got %+v\nwant %+v", got, a)
	}
	if got.AccountID() != a.SignPub {
		t.Fatalf("AccountID = %q, want sign_pub", got.AccountID())
	}
}

func TestLoadAccountMissing(t *testing.T) {
	if _, err := LoadAccount(t.TempDir()); err == nil || !strings.Contains(err.Error(), "lore init") {
		t.Fatalf("want missing-account error mentioning lore init, got %v", err)
	}
}

func TestDeviceRoundtripAndCertVerify(t *testing.T) {
	dir := t.TempDir()
	a, err := GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	d, err := GenerateDevice("laptop", a)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Cert.Verify(); err != nil {
		t.Fatalf("cert verify: %v", err)
	}
	if err := d.Cert.VerifyForAccount(a.AccountID()); err != nil {
		t.Fatalf("cert verify for account: %v", err)
	}
	if err := SaveDevice(dir, d); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDevice(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *d {
		t.Fatalf("loaded device differs")
	}
	if got.DeviceID() != d.DevicePub {
		t.Fatalf("DeviceID = %q, want device_pub", got.DeviceID())
	}

	// Tampered cert must fail.
	bad := d.Cert
	bad.Name = "evil"
	if err := bad.Verify(); err == nil {
		t.Fatal("tampered cert verified")
	}
	// Cert from another account must fail the pinned check.
	other, err := GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Cert.VerifyForAccount(other.AccountID()); err == nil {
		t.Fatal("cert verified against wrong account")
	}
}

func TestRecoveryCodeFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){9}$`)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(code) {
			t.Fatalf("bad recovery code format: %q", code)
		}
		if seen[code] {
			t.Fatalf("duplicate recovery code generated: %q", code)
		}
		seen[code] = true
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	if got := NormalizeRecoveryCode("abcd-efgh 1i2o"); got != "ABCDEFGH1120" {
		t.Fatalf("normalize = %q", got)
	}
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if NormalizeRecoveryCode(code) != NormalizeRecoveryCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))) {
		t.Fatal("normalization not stable across formatting variants")
	}
}
