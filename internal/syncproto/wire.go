package syncproto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// ProtocolVersion is sent in hello responses.
const ProtocolVersion = 1

// DeviceCertHeader carries the sender's device certificate (base64 of the
// keys.DeviceCert JSON) on every /lore/v1/* request. The server checks that
// the cert verifies AND that its device_pub equals the TLS-connection peer
// pubkey, which proves the connection peer is a device of cert.account_pub.
const DeviceCertHeader = "X-Lore-Device-Cert"

// Hello is the response of GET /lore/v1/hello. DeviceCert lets the caller
// verify the device -> account binding (used by TOFU peer pinning).
type Hello struct {
	DeviceID   string          `json:"device_id"`
	AccountID  string          `json:"account_id"`
	Name       string          `json:"name"`
	Version    int             `json:"version"`
	DeviceCert keys.DeviceCert `json:"device_cert"`
}

// SpacesRequest is the body of POST /lore/v1/spaces: the caller's blinded
// space ids. The response is the intersection with the server's.
type SpacesRequest struct {
	Blinded []string `json:"blinded"`
}

// SpacesResponse is the intersection of blinded space ids.
type SpacesResponse struct {
	Blinded []string `json:"blinded"`
}

// MemberDoc is one signed member-list document version, as stored.
type MemberDoc struct {
	Version int64  `json:"version"`
	Doc     string `json:"doc"`
	Sig     string `json:"sig"`
	Signer  string `json:"signer"`
}

// SyncRequest is the body of POST /lore/v1/sync: "here is what I have seen
// for this space; send me what I lack".
type SyncRequest struct {
	BlindedSpaceID string `json:"blinded_space_id"`
	VV             VV     `json:"vv"`
}

// SyncResponse returns the server's version vector plus the entry versions
// (full store.Entry JSON) the caller is missing, and the space's member docs.
type SyncResponse struct {
	VV         VV            `json:"vv"`
	Entries    []store.Entry `json:"entries"`
	MemberDocs []MemberDoc   `json:"member_docs"`
}

// EntriesRequest is the body of POST /lore/v1/entries (push direction).
type EntriesRequest struct {
	BlindedSpaceID string        `json:"blinded_space_id"`
	Entries        []store.Entry `json:"entries"`
}

// EntriesResponse reports how many pushed entries were applied (LWW may
// reject stale versions; that is not an error).
type EntriesResponse struct {
	Applied int `json:"applied"`
}

// EnrollInfo is the response of GET /lore/v1/enroll?challenge=<hex>: the
// enrollee's ephemeral X25519 pubkey plus an HMAC over challenge||eph_pub
// keyed with the (normalized) enroll code, proving the endpoint knows the
// code the human read off the new device's screen.
type EnrollInfo struct {
	EphPub string `json:"eph_pub"` // hex X25519 pubkey
	MAC    string `json:"mac"`     // hex HMAC-SHA256(code, challenge || eph_pub)
}

// EnrollRequest is the body of POST /lore/v1/enroll: the enrollment payload
// sealed to the enrollee's ephemeral pubkey with box.SealAnonymous.
type EnrollRequest struct {
	Box string `json:"box"` // base64(SealAnonymous(json(EnrollPayload)))
}

// EnrollPayload is the plaintext an approving device sends to a new device:
// the full account keys plus every space (including space_keys) so the new
// device can compute blinded ids and take part in sync immediately.
// (account.json alone is not enough: without the personal space's id+key the
// blinded-id intersection would never match — pinned as a contract addition.)
type EnrollPayload struct {
	Code    string        `json:"code"`
	Account keys.Account  `json:"account"`
	Spaces  []SpaceRecord `json:"spaces"`
}

// EnrollResponse acknowledges enrollment with the new device's identity.
type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
}

// SpaceRecord is a wire/vault representation of a spaces table row.
type SpaceRecord struct {
	SpaceID    string `json:"space_id"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	ProjectRef string `json:"project_ref"`
	SpaceKey   []byte `json:"space_key"`
	Pinned     bool   `json:"pinned"`
	CreatedAt  string `json:"created_at"`
}

// EncodeDeviceCert renders a device cert for the DeviceCertHeader.
func EncodeDeviceCert(c keys.DeviceCert) string {
	b, _ := json.Marshal(c)
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeDeviceCert parses and verifies a DeviceCertHeader value, returning
// the cert only if its account signature checks out.
func DecodeDeviceCert(header string) (keys.DeviceCert, error) {
	var c keys.DeviceCert
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return c, fmt.Errorf("device cert header: %w", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("device cert header: %w", err)
	}
	if err := c.Verify(); err != nil {
		return c, err
	}
	return c, nil
}

// SenderCert extracts and verifies the device cert from a request, checking
// it against the TLS-level peer pubkey. tlsPeerID comes from
// transport.PeerIDFromConn. This is the app-layer check every /lore/v1/*
// request must pass: TLS proves the peer holds device_priv; the cert proves
// that device key belongs to cert.AccountPub.
func SenderCert(r *http.Request, tlsPeerID string) (keys.DeviceCert, error) {
	h := r.Header.Get(DeviceCertHeader)
	if h == "" {
		return keys.DeviceCert{}, fmt.Errorf("missing %s header", DeviceCertHeader)
	}
	cert, err := DecodeDeviceCert(h)
	if err != nil {
		return keys.DeviceCert{}, err
	}
	if tlsPeerID == "" || cert.DevicePub != tlsPeerID {
		return keys.DeviceCert{}, fmt.Errorf("device cert does not match TLS peer identity")
	}
	return cert, nil
}
