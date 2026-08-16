package daemon

import (
	"context"
	"net"
	"strings"

	"github.com/BlueHeisenberg/agentmesh/pkg/discovery"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// mDNS name encoding
//
// pkg/discovery composes the TXT record internally (v=1, pk=<device id>,
// name=<name>) and is not extensible without editing agentmesh, so lore
// smuggles the account pubkey inside the name field:
//
//	daemon:   "acct:<hex account pub>|<display name>"
//	enrollee: "enroll|<display name>"
//
// The acct value in TXT is a HINT only (mDNS is unauthenticated); before a
// discovered peer is trusted for sync, harvestDiscovered fetches
// /lore/v1/hello over mTLS and verifies the device cert chain, storing the
// *verified* account in the peers table. The personal-space gate only ever
// consults that verified value.

// encodeName builds the daemon's advertised name.
func encodeAdvertiseName(accountID, display string) string {
	return "acct:" + accountID + "|" + display
}

// parseAdvertiseName extracts (accountHint, display) from a discovered name.
// ok=false for non-daemon advertisements (e.g. enrollees).
func parseAdvertiseName(name string) (acct, display string, ok bool) {
	rest, found := strings.CutPrefix(name, "acct:")
	if !found {
		return "", "", false
	}
	acct, display, found = strings.Cut(rest, "|")
	if !found || acct == "" {
		return "", "", false
	}
	return acct, display, true
}

// ifacesAndIPs returns the mDNS scope: loopback always; plus LAN interfaces
// and addresses when lan is set (same scoping approach as agentmesh).
func ifacesAndIPs(lan bool) ([]net.Interface, []string) {
	ifaces := discovery.LoopbackInterfaces()
	ips := []string{"127.0.0.1"}
	if lan {
		ifaces = append(ifaces, discovery.NonLoopbackMulticastInterfaces()...)
		ips = append(ips, discovery.LANIPv4s()...)
	}
	return ifaces, ips
}

// startDiscovery advertises this daemon and browses for others.
func (d *Daemon) startDiscovery(ctx context.Context) error {
	ifaces, ips := ifacesAndIPs(d.opts.LAN)
	stop, err := discovery.Advertise(ServiceType,
		encodeAdvertiseName(d.account.AccountID(), d.device.Name),
		d.device.DeviceID(), d.port, ifaces, ips)
	if err != nil {
		return err
	}
	d.stopAdv = stop
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		_ = discovery.Browse(ctx, ServiceType, d.reg, ifaces)
	}()
	return nil
}

// harvestDiscovered promotes mDNS registry entries to peers-table rows and
// returns the set of device ids currently advertising themselves. Peers we
// already know get their address and last_seen refreshed; unknown peers are
// verified first via an mTLS hello (device cert chain -> account) so the
// peers table only ever contains verified accounts.
//
// Being advertised IS being seen, whether or not the subsequent sync
// succeeds: that is what separates a peer that is present but failing (a
// fault worth reporting) from an address nobody answers to any more (a dead
// pod, to be forgotten). last_seen is therefore refreshed on every sighting,
// not only when the address changed.
func (d *Daemon) harvestDiscovered(ctx context.Context) map[string]bool {
	advertised := map[string]bool{}
	known := map[string]syncproto.Peer{}
	if peers, err := syncproto.ListPeers(d.db); err == nil {
		for _, p := range peers {
			known[p.DeviceID] = p
		}
	}
	for _, dp := range d.reg.List() {
		if dp.PeerID == d.device.DeviceID() {
			continue
		}
		_, display, ok := parseAdvertiseName(dp.Name)
		if !ok {
			continue // enrollee or foreign advertisement
		}
		if kp, seen := known[dp.PeerID]; seen {
			advertised[dp.PeerID] = true
			if !kp.Static {
				kp.Addr = dp.Addr
				kp.LastSeen = keys.Now()
				_ = syncproto.UpsertPeer(d.db, kp)
			}
			continue
		}
		// New peer: verify identity before trusting the TXT account hint.
		hello, err := helloPeer(ctx, d.client.HTTPFor(dp.PeerID), d.certHdr, dp.Addr)
		if err != nil {
			d.opts.Logf("hello %s (%s): %v", shortID(dp.PeerID), dp.Addr, err)
			continue
		}
		if hello.DeviceID != dp.PeerID {
			d.opts.Logf("hello %s: device id mismatch", dp.Addr)
			continue
		}
		advertised[hello.DeviceID] = true
		_ = syncproto.UpsertPeer(d.db, syncproto.Peer{
			DeviceID:   hello.DeviceID,
			AccountPub: hello.DeviceCert.AccountPub,
			Name:       display,
			Addr:       dp.Addr,
			Static:     false,
			LastSeen:   keys.Now(),
		})
	}
	return advertised
}
