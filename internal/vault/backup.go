package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// Backup dumps the store at home into an encrypted archive envelope.
func Backup(home, passphrase, recoveryCode string, kdf KDFParams) ([]byte, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, err
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	arch := Archive{
		V:          1,
		CreatedAt:  keys.Now(),
		Account:    *account,
		MemberDocs: map[string][]syncproto.MemberDoc{},
		Blobs:      map[string][]byte{},
	}
	arch.Spaces, err = syncproto.ListSpaceRecords(db)
	if err != nil {
		return nil, err
	}
	for _, sp := range arch.Spaces {
		docs, err := syncproto.MemberDocs(db, sp.SpaceID)
		if err != nil {
			return nil, err
		}
		if len(docs) > 0 {
			arch.MemberDocs[sp.SpaceID] = docs
		}
		entries, err := syncproto.AllEntries(db, sp.SpaceID)
		if err != nil {
			return nil, err
		}
		arch.Entries = append(arch.Entries, entries...)
	}
	arch.Attachments, err = syncproto.ListAttachments(db)
	if err != nil {
		return nil, err
	}
	for _, a := range arch.Attachments {
		if _, ok := arch.Blobs[a.BlobHash]; ok {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(home, "blobs", a.BlobHash)); err == nil {
			arch.Blobs[a.BlobHash] = b
		}
	}

	plain, err := marshalArchive(arch)
	if err != nil {
		return nil, err
	}
	return Seal(plain, passphrase, recoveryCode, kdf)
}

// Restore rebuilds a fresh LORE_HOME from an archive envelope: account.json
// restored verbatim, a NEW device keypair certified by the restored account
// key, and all store rows re-created (space ids and keys preserved so the
// restored device syncs with surviving peers immediately).
func Restore(home string, envelope []byte, passphrase, recoveryCode, deviceName string) error {
	if _, err := os.Stat(filepath.Join(home, keys.AccountFile)); err == nil {
		return fmt.Errorf("refusing to restore over existing account at %s", home)
	}
	plain, err := Open(envelope, passphrase, recoveryCode)
	if err != nil {
		return err
	}
	arch, err := unmarshalArchive(plain)
	if err != nil {
		return err
	}
	if arch.V != 1 {
		return fmt.Errorf("unsupported archive version %d", arch.V)
	}
	if err := arch.Account.VerifyEncPub(); err != nil {
		return fmt.Errorf("archive account keys invalid: %w", err)
	}

	if err := keys.SaveAccount(home, &arch.Account); err != nil {
		return err
	}
	if deviceName == "" {
		deviceName = "restored"
	}
	device, err := keys.GenerateDevice(deviceName, &arch.Account)
	if err != nil {
		return err
	}
	if err := keys.SaveDevice(home, device); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(home, "blobs"), 0o700); err != nil {
		return err
	}
	for hash, b := range arch.Blobs {
		if err := os.WriteFile(filepath.Join(home, "blobs", hash), b, 0o600); err != nil {
			return err
		}
	}

	priv, err := device.PrivateKey()
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID:  arch.Account.AccountID(),
		DeviceID:   device.DeviceID(),
		DevicePriv: priv,
	})
	if err != nil {
		return err
	}
	defer st.Close()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	for _, sp := range arch.Spaces {
		if err := syncproto.InsertSpaceRecord(db, sp); err != nil {
			return err
		}
		for _, doc := range arch.MemberDocs[sp.SpaceID] {
			if err := syncproto.InsertMemberDoc(db, sp.SpaceID, doc); err != nil {
				return err
			}
		}
	}
	for _, e := range arch.Entries {
		// Rows carry their original signatures and LWW metadata; ApplyRemote
		// re-inserts them verbatim (fresh DB: everything applies).
		if _, err := st.ApplyRemote(e); err != nil {
			return fmt.Errorf("restore entry %s: %w", e.EntryID, err)
		}
	}
	for _, a := range arch.Attachments {
		if err := syncproto.InsertAttachment(db, a); err != nil {
			return err
		}
	}
	return nil
}

func marshalArchive(a Archive) ([]byte, error) {
	return json.Marshal(a)
}

func unmarshalArchive(b []byte) (Archive, error) {
	var a Archive
	if err := json.Unmarshal(b, &a); err != nil {
		return a, errors.New("corrupt archive payload")
	}
	return a, nil
}
