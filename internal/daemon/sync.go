package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// doJSON runs one JSON round-trip against a pinned peer with our device
// cert header attached. (transport.Client.DoJSON cannot set headers, and
// the cert header is mandatory on every lore route, so we roll our own.)
func (d *Daemon) doJSON(ctx context.Context, peerDeviceID, method, url string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(syncproto.DeviceCertHeader, d.certHdr)
	resp, err := d.client.HTTPFor(peerDeviceID).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, b)
	}
	if respBody != nil {
		return json.NewDecoder(resp.Body).Decode(respBody)
	}
	return nil
}

// syncRound harvests discovered peers, then runs a spaces-intersection +
// per-space vv exchange (pull) + push against every known peer, and finally
// forgets the discovered peers that have gone quiet.
func (d *Daemon) syncRound(ctx context.Context) {
	var errs []string
	advertised := d.harvestDiscovered(ctx)

	peers, err := syncproto.ListPeers(d.db)
	if err != nil {
		d.setLastSync([]string{err.Error()})
		return
	}
	for _, p := range peers {
		if p.DeviceID == d.device.DeviceID() || p.Addr == "" {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if err := d.syncPeer(ctx, p); err != nil {
			d.opts.Logf("sync %s (%s): %v", shortID(p.DeviceID), p.Addr, err)
			// Not every failure is a fault. A discovered peer that is no
			// longer advertising itself is an address whose machine is gone —
			// on a container host that is every replaced pod, and reporting
			// each one every round is what buries the failure an operator
			// needed to see. It is still attempted (mDNS may be off, or the
			// peer reachable anyway) and it will be forgotten by
			// expireDiscovered; it is just not called an error. A static peer
			// is always reported: a person configured it, so its silence is
			// news.
			if p.Static || advertised[p.DeviceID] {
				errs = append(errs, fmt.Sprintf("%s: %v", shortID(p.DeviceID), err))
			}
		}
	}
	d.expireDiscovered()
	d.setLastSync(errs)
}

// expireDiscovered drops mDNS-discovered peers not seen — neither advertised
// nor successfully synced — for PeerTTL, and forgets what they shared.
func (d *Daemon) expireDiscovered() {
	cutoff := time.Now().UTC().Add(-d.opts.PeerTTL).Format(keys.TimeFormat)
	gone, err := syncproto.DeleteStalePeers(d.db, cutoff)
	if err != nil {
		d.opts.Logf("expire peers: %v", err)
		return
	}
	if len(gone) == 0 {
		return
	}
	d.mu.Lock()
	for _, id := range gone {
		delete(d.common, id)
	}
	d.mu.Unlock()
	for _, id := range gone {
		d.opts.Logf("forgot discovered peer %s: not seen for %s", shortID(id), d.opts.PeerTTL)
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// syncPeer runs the full exchange with one peer:
// blinded intersection -> per common space: pull (vv exchange) then push.
func (d *Daemon) syncPeer(ctx context.Context, p syncproto.Peer) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	base := "https://" + p.Addr

	mine, err := d.blindedSpaces(p.AccountPub)
	if err != nil {
		return err
	}
	if len(mine) == 0 {
		return nil
	}
	offer := make([]string, 0, len(mine))
	for b := range mine {
		offer = append(offer, b)
	}
	var common syncproto.SpacesResponse
	if err := d.doJSON(ctx, p.DeviceID, http.MethodPost, base+"/lore/v1/spaces",
		syncproto.SpacesRequest{Blinded: offer}, &common); err != nil {
		return err
	}
	d.recordCommon(p.DeviceID, common.Blinded, mine)

	personalTouched := false
	for _, blinded := range common.Blinded {
		sp, ok := mine[blinded]
		if !ok {
			continue // peer offered something we never asked about
		}
		applied, err := d.syncSpace(ctx, p, base, blinded, sp)
		if err != nil {
			return fmt.Errorf("space %s: %w", sp.Name, err)
		}
		if applied > 0 && sp.Kind == "personal" {
			personalTouched = true
		}
	}
	_ = syncproto.TouchPeer(d.db, p.DeviceID, keys.Now())
	if personalTouched {
		d.renderDistill()
	}
	return nil
}

// recordCommon remembers which of our spaces a peer turned out to hold, for
// GET /admin/status. It is recorded straight off the intersection response,
// before any per-space sync runs: "we both hold this space" is true whether
// or not the transfer that followed worked.
//
// The intersection can only ever name spaces WE hold — the peer answers our
// offer with a subset of it — so recording it discloses nothing we did not
// already have. Blinded ids are translated back to local space ids here: the
// blinded form is a wire encoding whose only purpose is to keep the id off
// the network, and a caller of the loopback admin API is not the network.
func (d *Daemon) recordCommon(deviceID string, blinded []string, mine map[string]store.Space) {
	ids := make([]string, 0, len(blinded))
	for _, b := range blinded {
		if sp, ok := mine[b]; ok {
			ids = append(ids, sp.SpaceID)
		}
	}
	sort.Strings(ids)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.common == nil {
		d.common = map[string][]string{}
	}
	d.common[deviceID] = ids
}

// syncSpace does one pull+push cycle for a single common space. Returns how
// many remote entry versions were applied locally.
func (d *Daemon) syncSpace(ctx context.Context, p syncproto.Peer, base, blinded string, sp store.Space) (int, error) {
	localVV, err := syncproto.LocalVV(d.db, sp.SpaceID)
	if err != nil {
		return 0, err
	}

	// Pull: send our vv, receive what we lack.
	var resp syncproto.SyncResponse
	if err := d.doJSON(ctx, p.DeviceID, http.MethodPost, base+"/lore/v1/sync",
		syncproto.SyncRequest{BlindedSpaceID: blinded, VV: localVV}, &resp); err != nil {
		return 0, err
	}
	// Member docs BEFORE entries: applying shared-space entries requires the
	// verified member list, which may arrive in the same response.
	if err := syncproto.MergeMemberDocs(d.db, sp.SpaceID, resp.MemberDocs); err != nil {
		return 0, err
	}
	applied, err := syncproto.ApplyEntries(d.st, sp, resp.Entries,
		syncproto.MemberDocCheck(d.db, d.account.AccountID()))
	if err != nil {
		return applied, err
	}

	// Push: everything the peer's vv does not cover, docs alongside so a
	// receiver that never pulled from us can still verify membership.
	missing, err := syncproto.EntriesSince(d.db, sp.SpaceID, resp.VV)
	if err != nil {
		return applied, err
	}
	if len(missing) > 0 {
		docs, err := syncproto.MemberDocs(d.db, sp.SpaceID)
		if err != nil {
			return applied, err
		}
		var pushResp syncproto.EntriesResponse
		if err := d.doJSON(ctx, p.DeviceID, http.MethodPost, base+"/lore/v1/entries",
			syncproto.EntriesRequest{BlindedSpaceID: blinded, Entries: missing, MemberDocs: docs}, &pushResp); err != nil {
			return applied, err
		}
	}

	// Bookkeeping: record the highest seqs we know the peer holds.
	merged := localVV.Merge(resp.VV)
	for dev, seq := range merged {
		_ = syncproto.SetSyncState(d.db, sp.SpaceID, dev, seq)
	}
	return applied, nil
}
