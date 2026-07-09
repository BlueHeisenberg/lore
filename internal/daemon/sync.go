package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
// per-space vv exchange (pull) + push against every known peer.
func (d *Daemon) syncRound(ctx context.Context) {
	var errs []string
	d.harvestDiscovered(ctx)

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
			errs = append(errs, fmt.Sprintf("%s: %v", shortID(p.DeviceID), err))
			d.opts.Logf("sync %s (%s): %v", shortID(p.DeviceID), p.Addr, err)
		}
	}
	d.setLastSync(errs)
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
