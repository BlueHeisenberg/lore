// Package syncproto is the shared device-to-device sync layer: version
// vectors, blinded space ids, the wire types for the /lore/v1/* routes, and
// the verified receive path (signature -> membership -> LWW apply).
// The protocol is pinned by docs/IMPLEMENTATION.md §Sync protocol.
package syncproto

// VV is a version vector for one space: device_id (hex device pubkey) ->
// highest device_seq observed from that device. A device that has entries
// with device_seq up to N from device D has seen everything D wrote up to N,
// because device_seq is per-(space, device) monotonic.
type VV map[string]int64

// Merge returns the pointwise max of v and o (neither input is modified).
func (v VV) Merge(o VV) VV {
	out := make(VV, len(v)+len(o))
	for k, n := range v {
		out[k] = n
	}
	for k, n := range o {
		if n > out[k] {
			out[k] = n
		}
	}
	return out
}

// Covers reports whether v has seen at least everything o has:
// for every device in o, v[device] >= o[device].
func (v VV) Covers(o VV) bool {
	for k, n := range o {
		if v[k] < n {
			return false
		}
	}
	return true
}

// Since reports whether an entry version (origin device + device_seq) is
// NOT yet covered by v — i.e. the holder of v is missing it.
func (v VV) Since(originDevice string, deviceSeq int64) bool {
	return deviceSeq > v[originDevice]
}

// Clone returns a copy of v (nil-safe).
func (v VV) Clone() VV {
	out := make(VV, len(v))
	for k, n := range v {
		out[k] = n
	}
	return out
}
