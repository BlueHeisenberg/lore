package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Body size caps. The auth middleware must buffer the body to hash it, so a
// hard global cap protects memory; routes apply their own tighter caps.
const (
	maxLogDelta    = 4 << 20  // POST .../log
	maxKeybox      = 64 << 10 // PUT /v1/account/keybox
	maxSnapshot    = 32 << 20 // PUT .../snapshot (full compacted space state)
	maxSmallBody   = 64 << 10 // JSON control bodies
	maxWaitSeconds = 60       // long-poll cap
)

// Config mirrors configs/env.example exactly.
type Config struct {
	Addr                string // LORE_RELAY_ADDR (default :8480)
	DataDir             string // LORE_RELAY_DATA
	QuotaMB             int64  // LORE_RELAY_QUOTA_MB (default 100)
	StripeSecretKey     string // STRIPE_SECRET_KEY (unused server-side beyond presence)
	StripeWebhookSecret string // STRIPE_WEBHOOK_SECRET (empty = webhook 503)
	StripePriceID       string // STRIPE_PRICE_ID
}

// ConfigFromEnv reads the env contract from configs/env.example.
func ConfigFromEnv() Config {
	cfg := Config{
		Addr:                os.Getenv("LORE_RELAY_ADDR"),
		DataDir:             os.Getenv("LORE_RELAY_DATA"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripePriceID:       os.Getenv("STRIPE_PRICE_ID"),
		QuotaMB:             100,
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8480"
	}
	if v := os.Getenv("LORE_RELAY_QUOTA_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.QuotaMB = n
		}
	}
	return cfg
}

// Server is the relay HTTP server.
type Server struct {
	store      *Store
	nonces     *challenges
	quotaBytes int64
	cfg        Config
	logger     *log.Logger

	// keyboxLimiter guards the unauthenticated GET /v1/accounts/{handle}/keybox.
	keyboxLimiter *rateLimiter
	// inviteLimiter guards the unauthenticated GET /v1/invites/{addr}.
	inviteLimiter *rateLimiter

	// invite expiry sweep throttle (piggybacks on challenge traffic).
	inviteSweepMu   sync.Mutex
	lastInviteSweep time.Time

	// long-poll wakeups: one broadcast channel per blinded_id, closed and
	// replaced on every append.
	pollMu   sync.Mutex
	pollChan map[string]chan struct{}
}

// NewServer opens the store under cfg.DataDir and returns the server.
func NewServer(cfg Config, logger *log.Logger) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("relay: LORE_RELAY_DATA is required")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return &Server{
		store:         st,
		nonces:        newChallenges(),
		quotaBytes:    cfg.QuotaMB << 20,
		cfg:           cfg,
		logger:        logger,
		keyboxLimiter: newRateLimiter(5),
		inviteLimiter: newRateLimiter(10),
		pollChan:      make(map[string]chan struct{}),
	}, nil
}

// Close releases the underlying store.
func (s *Server) Close() error { return s.store.Close() }

// Store exposes the store (admin, tests).
func (s *Server) Store() *Store { return s.store }

// notifyAppend wakes all long-pollers of a space.
func (s *Server) notifyAppend(blindedID string) {
	s.pollMu.Lock()
	defer s.pollMu.Unlock()
	if ch, ok := s.pollChan[blindedID]; ok {
		close(ch)
		delete(s.pollChan, blindedID)
	}
}

// appendSignal returns a channel that closes on the next append to the space.
func (s *Server) appendSignal(blindedID string) <-chan struct{} {
	s.pollMu.Lock()
	defer s.pollMu.Unlock()
	ch, ok := s.pollChan[blindedID]
	if !ok {
		ch = make(chan struct{})
		s.pollChan[blindedID] = ch
	}
	return ch
}

// Handler builds the full route table.
//
//	POST   /v1/challenge                          (open)   mint auth nonce
//	POST   /v1/devices                            (sig*)   self-enroll device
//	POST   /v1/spaces                             (auth)   register space
//	POST   /v1/spaces/{id}/grant                  (auth)   owner grants access
//	DELETE /v1/spaces/{id}/grant/{account}        (auth)   owner revokes access
//	POST   /v1/spaces/{id}/log                    (auth)   append encrypted delta
//	GET    /v1/spaces/{id}/log?from=N&wait=S      (auth)   read/long-poll deltas
//	GET    /v1/spaces/{id}/snapshot               (auth)   fetch snapshot
//	PUT    /v1/spaces/{id}/snapshot?upto=N        (auth)   compact (any member)
//	PUT    /v1/account/keybox                     (auth)   store wrapped account key
//	GET    /v1/account/keybox                     (auth)   fetch own keybox
//	POST   /v1/account/handle                     (auth)   claim handle
//	GET    /v1/accounts/{handle}                  (open)   handle -> account_pub
//	GET    /v1/accounts/{handle}/keybox           (open, 5/min/IP) keybox for fresh login
//	POST   /v1/invites                            (auth)   park an invite-link blob
//	GET    /v1/invites/claims                     (auth)   pending claims on own invites
//	GET    /v1/invites/{addr}                     (open, 10/min/IP) fetch invite blob
//	POST   /v1/invites/{addr}/claims              (auth)   park a join claim
//	POST   /v1/invites/{addr}/processed           (auth)   owner: drop processed claims
//	DELETE /v1/invites/{addr}                     (auth)   owner: revoke
//	POST   /v1/stripe/webhook                     (Stripe sig) plan transitions
//
// (sig*) = challenge-signed by the enrolling device key + account_sig by the
// account key; the device need not be enrolled yet.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	mux.Handle("POST /v1/devices", s.authed(s.handleEnrollDevice, false))

	mux.Handle("POST /v1/spaces", s.authed(s.handleRegisterSpace, true))
	mux.Handle("POST /v1/spaces/{id}/grant", s.authed(s.handleGrant, true))
	mux.Handle("DELETE /v1/spaces/{id}/grant/{account}", s.authed(s.handleRevoke, true))
	mux.Handle("POST /v1/spaces/{id}/log", s.authed(s.handleAppendLog, true))
	mux.Handle("GET /v1/spaces/{id}/log", s.authed(s.handleReadLog, true))
	mux.Handle("GET /v1/spaces/{id}/snapshot", s.authed(s.handleGetSnapshot, true))
	mux.Handle("PUT /v1/spaces/{id}/snapshot", s.authed(s.handlePutSnapshot, true))

	mux.Handle("PUT /v1/account/keybox", s.authed(s.handlePutKeybox, true))
	mux.Handle("GET /v1/account/keybox", s.authed(s.handleGetKeybox, true))
	mux.Handle("POST /v1/account/handle", s.authed(s.handleClaimHandle, true))

	mux.HandleFunc("GET /v1/accounts/{handle}", s.handleResolveHandle)
	mux.HandleFunc("GET /v1/accounts/{handle}/keybox", s.handleHandleKeybox)

	mux.Handle("POST /v1/invites", s.authed(s.handleCreateInvite, true))
	mux.Handle("GET /v1/invites/claims", s.authed(s.handleListInviteClaims, true))
	mux.HandleFunc("GET /v1/invites/{addr}", s.handleGetInvite)
	mux.Handle("POST /v1/invites/{addr}/claims", s.authed(s.handlePostInviteClaim, true))
	mux.Handle("POST /v1/invites/{addr}/processed", s.authed(s.handleInviteProcessed, true))
	mux.Handle("DELETE /v1/invites/{addr}", s.authed(s.handleRevokeInvite, true))

	mux.HandleFunc("POST /v1/stripe/webhook", s.handleStripeWebhook)

	return s.logMiddleware(mux)
}

// authedRequest carries the verified caller identity into handlers.
type authedRequest struct {
	devicePub  string
	accountPub string // empty when requireEnrolled == false and device unknown
	body       []byte
}

type authedHandler func(w http.ResponseWriter, r *http.Request, a *authedRequest)

// authed verifies the challenge-signature headers. When requireEnrolled is
// true the device must already exist in devices and accountPub is resolved;
// POST /v1/devices passes false and proves account ownership itself.
func (s *Server) authed(h authedHandler, requireEnrolled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxSnapshot+1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		devicePub, err := s.verifyAuth(r, body)
		if err != nil {
			httpError(w, http.StatusUnauthorized, err.Error())
			return
		}
		a := &authedRequest{devicePub: devicePub, body: body}
		if requireEnrolled {
			acct, err := s.store.DeviceAccount(devicePub)
			if err != nil {
				httpError(w, http.StatusUnauthorized, "device not enrolled")
				return
			}
			a.accountPub = acct
		}
		h(w, r, a)
	})
}

// --- logging middleware: method path status bytes ms (never the body) ---

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

// Flush lets long-poll responses stream through the wrapper.
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.logger.Printf("%s %s %d %d %dms", r.Method, r.URL.Path, sw.status, sw.bytes,
			time.Since(start).Milliseconds())
	})
}

// --- small helpers ---

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// storeError maps store/policy errors onto HTTP statuses.
func storeError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, ErrNotFound):
		httpError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		httpError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrPlanPolicy):
		httpError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrQuotaExceeded):
		httpError(w, http.StatusInsufficientStorage, err.Error())
	case errors.Is(err, ErrBadInput):
		httpError(w, http.StatusBadRequest, err.Error())
	default:
		httpError(w, http.StatusInternalServerError, "internal error")
	}
}
