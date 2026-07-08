package syncproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// blindContext is the domain-separation prefix for space-id blinding.
const blindContext = "lore-blind"

// BlindSpaceID computes the blinded space identifier exchanged on the wire:
// hex(HMAC-SHA256(space_key, "lore-blind" || space_id)). Peers that hold the
// same space (and therefore its key) compute the same value; anyone else
// learns nothing about the space id from it.
func BlindSpaceID(spaceKey []byte, spaceID string) string {
	m := hmac.New(sha256.New, spaceKey)
	m.Write([]byte(blindContext))
	m.Write([]byte(spaceID))
	return hex.EncodeToString(m.Sum(nil))
}
