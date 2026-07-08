package relay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// --- auth bootstrap ---

// handleChallenge: POST /v1/challenge {device_pub} -> {nonce}.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DevicePub string `json:"device_pub"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := ParsePub(req.DevicePub); err != nil {
		httpError(w, http.StatusBadRequest, "device_pub must be a hex Ed25519 public key")
		return
	}
	nonce, err := s.nonces.issue(req.DevicePub)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"nonce": nonce})
}

// handleEnrollDevice: POST /v1/devices — self-enrollment. The request is
// challenge-signed by the (not yet enrolled) device key; the body carries
// account_sig = Ed25519(account_priv, "lore-enroll"||device_pub) proving the
// account authorizes this device. First device of an unknown account creates
// the account row with plan 'trial'.
func (s *Server) handleEnrollDevice(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	var req struct {
		AccountPub string `json:"account_pub"`
		DevicePub  string `json:"device_pub"`
		Cert       string `json:"cert"`
		AccountSig string `json:"account_sig"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.DevicePub != a.devicePub {
		httpError(w, http.StatusBadRequest, "device_pub must match X-Lore-Device")
		return
	}
	if _, err := ParsePub(req.AccountPub); err != nil {
		httpError(w, http.StatusBadRequest, "account_pub must be a hex Ed25519 public key")
		return
	}
	if err := verifyEnrollSig(req.AccountPub, req.DevicePub, req.AccountSig); err != nil {
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.store.EnrollDevice(req.AccountPub, req.DevicePub, req.Cert); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account_pub": req.AccountPub, "device_pub": req.DevicePub})
}

// --- spaces ---

// handleRegisterSpace: POST /v1/spaces {blinded_id} — idempotent register,
// owner = caller's account, owner granted access.
func (s *Server) handleRegisterSpace(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	var req struct {
		BlindedID string `json:"blinded_id"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil || !ValidBlindedID(req.BlindedID) {
		httpError(w, http.StatusBadRequest, "blinded_id must match [A-Za-z0-9_-]{8,128}")
		return
	}
	// Policy applies only to NEW rows; re-registering an owned space is a no-op.
	if _, err := s.store.SpaceOwner(req.BlindedID); errors.Is(err, ErrNotFound) {
		if err := s.checkPolicy(a.accountPub, actionCreateSpace, req.BlindedID, 0); err != nil {
			storeError(w, err)
			return
		}
	}
	if err := s.store.RegisterSpace(req.BlindedID, a.accountPub); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"blinded_id": req.BlindedID})
}

// requireOwner resolves the {id} path segment and checks the caller owns it.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, a *authedRequest) (string, bool) {
	id := r.PathValue("id")
	if !ValidBlindedID(id) {
		httpError(w, http.StatusBadRequest, "invalid blinded id")
		return "", false
	}
	owner, err := s.store.SpaceOwner(id)
	if err != nil {
		storeError(w, err)
		return "", false
	}
	if owner != a.accountPub {
		httpError(w, http.StatusForbidden, "only the space owner may manage access")
		return "", false
	}
	return id, true
}

// requireAccess resolves {id} and checks the caller's account holds access.
func (s *Server) requireAccess(w http.ResponseWriter, r *http.Request, a *authedRequest) (string, bool) {
	id := r.PathValue("id")
	if !ValidBlindedID(id) {
		httpError(w, http.StatusBadRequest, "invalid blinded id")
		return "", false
	}
	if _, err := s.store.SpaceOwner(id); err != nil {
		storeError(w, err)
		return "", false
	}
	ok, err := s.store.HasAccess(id, a.accountPub)
	if err != nil {
		storeError(w, err)
		return "", false
	}
	if !ok {
		httpError(w, http.StatusForbidden, "no access to this space")
		return "", false
	}
	return id, true
}

// handleGrant: POST /v1/spaces/{id}/grant {account_pub} (owner only).
func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireOwner(w, r, a)
	if !ok {
		return
	}
	var req struct {
		AccountPub string `json:"account_pub"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := ParsePub(req.AccountPub); err != nil {
		httpError(w, http.StatusBadRequest, "account_pub must be a hex Ed25519 public key")
		return
	}
	// The grantee must be a known account (invitees enroll before joining).
	if _, err := s.store.GetAccount(req.AccountPub); err != nil {
		storeError(w, err)
		return
	}
	if has, err := s.store.HasAccess(id, req.AccountPub); err != nil {
		storeError(w, err)
		return
	} else if !has { // policy counts only NEW grants
		if err := s.checkPolicy(a.accountPub, actionGrant, id, 0); err != nil {
			storeError(w, err)
			return
		}
	}
	if err := s.store.Grant(id, req.AccountPub); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"blinded_id": id, "account_pub": req.AccountPub})
}

// handleRevoke: DELETE /v1/spaces/{id}/grant/{account} (owner only).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireOwner(w, r, a)
	if !ok {
		return
	}
	target := r.PathValue("account")
	if _, err := ParsePub(target); err != nil {
		httpError(w, http.StatusBadRequest, "invalid account key in path")
		return
	}
	if err := s.store.Revoke(id, target); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- log ---

// handleAppendLog: POST /v1/spaces/{id}/log — body is the raw encrypted
// delta (opaque). Quota is enforced against the space OWNER before writing.
func (s *Server) handleAppendLog(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireAccess(w, r, a)
	if !ok {
		return
	}
	if len(a.body) == 0 {
		httpError(w, http.StatusBadRequest, "empty delta")
		return
	}
	if len(a.body) > maxLogDelta {
		httpError(w, http.StatusRequestEntityTooLarge, "delta exceeds 4 MB cap")
		return
	}
	owner, err := s.store.SpaceOwner(id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.checkPolicy(owner, actionStoreBytes, id, int64(len(a.body))); err != nil {
		storeError(w, err)
		return
	}
	seq, err := s.store.AppendLog(id, a.body)
	if err != nil {
		storeError(w, err)
		return
	}
	s.notifyAppend(id)
	writeJSON(w, http.StatusOK, map[string]int64{"seq": seq})
}

// logItem is one element of the GET log response.
type logItem struct {
	Seq  int64  `json:"seq"`
	Data string `json:"data"` // base64(std) of the encrypted delta
}

// handleReadLog: GET /v1/spaces/{id}/log?from=N&wait=S — returns a JSON
// array of {seq, data}; long-polls up to S seconds when empty, then 204.
// "from" is the first sequence wanted (clients pass last_seen+1).
func (s *Server) handleReadLog(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireAccess(w, r, a)
	if !ok {
		return
	}
	from := int64(1)
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			httpError(w, http.StatusBadRequest, "invalid from")
			return
		}
		from = max(n, 1)
	}
	wait := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			httpError(w, http.StatusBadRequest, "invalid wait")
			return
		}
		wait = min(n, maxWaitSeconds)
	}

	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		// Arm the wakeup BEFORE reading so an append between read and wait
		// cannot be missed.
		signal := s.appendSignal(id)
		entries, err := s.store.ReadLog(id, from, 256, maxLogDelta)
		if err != nil {
			storeError(w, err)
			return
		}
		if len(entries) > 0 {
			items := make([]logItem, len(entries))
			for i, e := range entries {
				items[i] = logItem{Seq: e.Seq, Data: base64.StdEncoding.EncodeToString(e.Data)}
			}
			writeJSON(w, http.StatusOK, items)
			return
		}
		remaining := time.Until(deadline)
		if wait == 0 || remaining <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-signal:
			// woken by an append; loop and re-read
		case <-time.After(remaining):
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// --- snapshot ---

// handleGetSnapshot: GET /v1/spaces/{id}/snapshot — raw bytes + X-Lore-Upto.
func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireAccess(w, r, a)
	if !ok {
		return
	}
	data, upto, err := s.store.GetSnapshot(id)
	if err != nil {
		storeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Lore-Upto", strconv.FormatInt(upto, 10))
	w.Write(data)
}

// handlePutSnapshot: PUT /v1/spaces/{id}/snapshot?upto=N — store a compacted
// snapshot and drop log rows/files with seq <= N. Per RELAY.md compaction is
// performed by "a device" of the space — ANY access holder may compact (the
// snapshot is opaque and author-signed inside; a malicious member can at
// worst destroy availability it already had rights to, never confidentiality).
func (s *Server) handlePutSnapshot(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	id, ok := s.requireAccess(w, r, a)
	if !ok {
		return
	}
	upto, err := strconv.ParseInt(r.URL.Query().Get("upto"), 10, 64)
	if err != nil || upto < 0 {
		httpError(w, http.StatusBadRequest, "upto query parameter required (>= 0)")
		return
	}
	if len(a.body) == 0 {
		httpError(w, http.StatusBadRequest, "empty snapshot")
		return
	}
	if len(a.body) > maxSnapshot {
		httpError(w, http.StatusRequestEntityTooLarge, "snapshot exceeds cap")
		return
	}
	owner, err := s.store.SpaceOwner(id)
	if err != nil {
		storeError(w, err)
		return
	}
	// Net growth = new snapshot - old snapshot - folded log bytes.
	var oldSnap, folded int64
	s.store.db.QueryRow(`SELECT size FROM snapshots WHERE blinded_id=?`, id).Scan(&oldSnap)
	s.store.db.QueryRow(`SELECT COALESCE(SUM(size),0) FROM log_index WHERE blinded_id=? AND seq<=?`,
		id, upto).Scan(&folded)
	if err := s.checkPolicy(owner, actionStoreBytes, id, int64(len(a.body))-oldSnap-folded); err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.PutSnapshot(id, upto, a.body); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"upto": upto})
}

// --- account keybox & handle ---

// handlePutKeybox: PUT /v1/account/keybox — raw wrapped account key <= 64KB.
func (s *Server) handlePutKeybox(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	if len(a.body) == 0 {
		httpError(w, http.StatusBadRequest, "empty keybox")
		return
	}
	if len(a.body) > maxKeybox {
		httpError(w, http.StatusRequestEntityTooLarge, "keybox exceeds 64 KB cap")
		return
	}
	var oldLen int64
	s.store.db.QueryRow(`SELECT COALESCE(LENGTH(keybox),0) FROM accounts WHERE account_pub=?`,
		a.accountPub).Scan(&oldLen)
	if err := s.checkPolicy(a.accountPub, actionStoreBytes, "", int64(len(a.body))-oldLen); err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.PutKeybox(a.accountPub, a.body); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetKeybox: GET /v1/account/keybox — own wrapped key (device auth).
func (s *Server) handleGetKeybox(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	kb, err := s.store.GetKeybox(a.accountPub)
	if err != nil {
		storeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(kb)
}

// handleClaimHandle: POST /v1/account/handle {handle}.
func (s *Server) handleClaimHandle(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	var req struct {
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.ClaimHandle(a.accountPub, req.Handle); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"handle": req.Handle})
}

// handleResolveHandle: GET /v1/accounts/{handle} — unauthenticated invite
// discovery (opt-in by claiming a handle).
func (s *Server) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	if !ValidHandle(handle) {
		httpError(w, http.StatusBadRequest, "invalid handle")
		return
	}
	pub, err := s.store.AccountByHandle(handle)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account_pub": pub})
}

// handleHandleKeybox: GET /v1/accounts/{handle}/keybox — UNAUTHENTICATED by
// design: fresh login has no enrolled device yet. Possessing the handle
// yields only Argon2id-wrapped bytes (useless without passphrase + recovery
// code). Rate-limited 5/min/IP against enumeration/offline-harvest attempts.
func (s *Server) handleHandleKeybox(w http.ResponseWriter, r *http.Request) {
	if !s.keyboxLimiter.allow(clientIP(r)) {
		httpError(w, http.StatusTooManyRequests, "rate limit: 5/min")
		return
	}
	handle := r.PathValue("handle")
	if !ValidHandle(handle) {
		httpError(w, http.StatusBadRequest, "invalid handle")
		return
	}
	pub, err := s.store.AccountByHandle(handle)
	if err != nil {
		storeError(w, err)
		return
	}
	kb, err := s.store.GetKeybox(pub)
	if err != nil {
		storeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(kb)
}

// decodeJSON reads a small JSON body with a size cap.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxSmallBody))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body")
	}
	return nil
}
