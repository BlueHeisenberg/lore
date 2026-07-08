package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/agentmesh/pkg/identity"
	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// helloPeer fetches /lore/v1/hello with an already-pinned client and
// verifies the response's device cert chain.
func helloPeer(ctx context.Context, httpc *http.Client, certHdr, addr string) (syncproto.Hello, error) {
	var hello syncproto.Hello
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/lore/v1/hello", nil)
	if err != nil {
		return hello, err
	}
	req.Header.Set(syncproto.DeviceCertHeader, certHdr)
	resp, err := httpc.Do(req)
	if err != nil {
		return hello, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return hello, fmt.Errorf("hello %s: %s: %s", addr, resp.Status, b)
	}
	if err := json.NewDecoder(resp.Body).Decode(&hello); err != nil {
		return hello, err
	}
	return hello, verifyHello(hello)
}

func verifyHello(h syncproto.Hello) error {
	if err := h.DeviceCert.Verify(); err != nil {
		return err
	}
	if h.DeviceCert.DevicePub != h.DeviceID {
		return fmt.Errorf("hello device cert names a different device")
	}
	if h.DeviceCert.AccountPub != h.AccountID {
		return fmt.Errorf("hello account does not match device cert")
	}
	return nil
}

// AddStaticPeer registers host:port as a static sync peer for the store at
// home. The peer's device_id is unknown until first contact, so this is a
// TOFU (trust-on-first-use) exchange:
//
//  1. Connect with client mTLS but without server pinning — the server cert
//     is only checked to be a valid self-signed Ed25519 identity cert
//     (transport.VerifySelfSignedCert), because we do not yet know which
//     device key to expect at that address.
//  2. GET /lore/v1/hello; require the claimed device_id to equal the TLS
//     connection's actual peer pubkey, and the device cert to chain that
//     key to an account.
//  3. Pin: store (device_id, account_pub, addr, static=1) in the peers
//     table. Every subsequent sync pins TLS to that device_id, so an
//     attacker who was not present at first contact can never impersonate
//     the peer. (An attacker who IS the first contact owns the pin — the
//     standard TOFU trade-off; personal-space data additionally requires
//     the account gate, which an attacker cannot pass without account keys.)
func AddStaticPeer(home, addr string) (syncproto.Peer, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return syncproto.Peer{}, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return syncproto.Peer{}, err
	}
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return syncproto.Peer{}, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return syncproto.Peer{}, err
	}
	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		return syncproto.Peer{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hello, tlsPeerID, err := helloUnpinned(ctx, cert, syncproto.EncodeDeviceCert(device.Cert), addr)
	if err != nil {
		return syncproto.Peer{}, err
	}
	if hello.DeviceID != tlsPeerID {
		return syncproto.Peer{}, fmt.Errorf("peer at %s claims device %s but its TLS key is %s",
			addr, shortID(hello.DeviceID), shortID(tlsPeerID))
	}

	p := syncproto.Peer{
		DeviceID:   hello.DeviceID,
		AccountPub: hello.DeviceCert.AccountPub,
		Name:       hello.Name,
		Addr:       addr,
		Static:     true,
		LastSeen:   keys.Now(),
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return syncproto.Peer{}, err
	}
	defer db.Close()
	if err := syncproto.UpsertPeer(db, p); err != nil {
		return syncproto.Peer{}, err
	}
	return p, nil
}

// helloUnpinned is step 1+2 of the TOFU exchange: fetch hello over mTLS
// without server pinning, returning the hello and the TLS-proven peer id.
func helloUnpinned(ctx context.Context, cert tls.Certificate, certHdr, addr string) (syncproto.Hello, string, error) {
	var tlsPeerID string
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // verified manually: self-signed identity cert
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			if err := transport.VerifySelfSignedCert(rawCerts, chains); err != nil {
				return err
			}
			c, _ := x509.ParseCertificate(rawCerts[0])
			tlsPeerID = hex.EncodeToString(c.PublicKey.(ed25519.PublicKey))
			return nil
		},
	}
	httpc := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
	hello, err := helloPeer(ctx, httpc, certHdr, addr)
	if err != nil {
		return hello, "", err
	}
	return hello, tlsPeerID, nil
}
