package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// stripeTolerance rejects webhook timestamps older/newer than this.
const stripeTolerance = 5 * time.Minute

// verifyStripeSignature implements Stripe's v1 webhook scheme by hand (no
// SDK dependency): header "Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]",
// expected = HMAC-SHA256(secret, t + "." + body), constant-time compare
// against every v1 candidate, timestamp within tolerance of now.
func verifyStripeSignature(header string, body []byte, secret string, now time.Time) error {
	var ts int64 = -1
	var candidates []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return errors.New("stripe: bad timestamp")
			}
			ts = n
		case "v1":
			candidates = append(candidates, v)
		}
	}
	if ts < 0 || len(candidates) == 0 {
		return errors.New("stripe: signature header missing t= or v1=")
	}
	age := now.Sub(time.Unix(ts, 0))
	if age > stripeTolerance || age < -stripeTolerance {
		return errors.New("stripe: timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)
	for _, c := range candidates {
		got, err := hex.DecodeString(c)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, got) {
			return nil
		}
	}
	return errors.New("stripe: no matching v1 signature")
}

// stripeEvent is the minimal envelope we care about.
type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Object struct {
			Customer string            `json:"customer"`
			Status   string            `json:"status"`
			Metadata map[string]string `json:"metadata"`
		} `json:"object"`
	} `json:"data"`
}

// handleStripeWebhook: POST /v1/stripe/webhook. 503 when billing is disabled
// (STRIPE_WEBHOOK_SECRET unset). Plan transitions:
//
//	checkout.session.completed        -> plan 'paid' for metadata.account_pub,
//	                                     store the Stripe customer id
//	customer.subscription.updated     -> status active|trialing -> 'paid', else 'free'
//	customer.subscription.deleted     -> 'free'
//
// Subscription events resolve the account via metadata.account_pub when
// present, else via the stored stripe_customer id.
func (s *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StripeWebhookSecret == "" {
		httpError(w, http.StatusServiceUnavailable, "billing disabled (no STRIPE_WEBHOOK_SECRET)")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	if err := verifyStripeSignature(r.Header.Get("Stripe-Signature"), body, s.cfg.StripeWebhookSecret, time.Now()); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ev stripeEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		httpError(w, http.StatusBadRequest, "invalid event JSON")
		return
	}

	apply := func() error {
		switch ev.Type {
		case "checkout.session.completed":
			acct := ev.Data.Object.Metadata["account_pub"]
			if acct == "" {
				return fmt.Errorf("checkout.session.completed without metadata.account_pub")
			}
			if err := s.store.SetPlan(acct, "paid"); err != nil {
				return err
			}
			if ev.Data.Object.Customer != "" {
				return s.store.SetStripeCustomer(acct, ev.Data.Object.Customer)
			}
			return nil
		case "customer.subscription.updated":
			plan := "free"
			if st := ev.Data.Object.Status; st == "active" || st == "trialing" {
				plan = "paid"
			}
			return s.setPlanForEvent(&ev, plan)
		case "customer.subscription.deleted":
			return s.setPlanForEvent(&ev, "free")
		default:
			return nil // acknowledge unhandled event types
		}
	}

	if err := apply(); err != nil {
		// Unknown account: acknowledge (200) so Stripe stops retrying a
		// webhook we can never apply, but log it.
		if errors.Is(err, ErrNotFound) {
			s.logger.Printf("stripe: %s for unknown account/customer", ev.Type)
			writeJSON(w, http.StatusOK, map[string]string{"received": "true"})
			return
		}
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"received": "true"})
}

// setPlanForEvent resolves the target account (metadata.account_pub first,
// then the stored stripe_customer binding) and sets its plan.
func (s *Server) setPlanForEvent(ev *stripeEvent, plan string) error {
	if acct := ev.Data.Object.Metadata["account_pub"]; acct != "" {
		return s.store.SetPlan(acct, plan)
	}
	if cust := ev.Data.Object.Customer; cust != "" {
		return s.store.SetPlanByCustomer(cust, plan)
	}
	return fmt.Errorf("subscription event without metadata.account_pub or customer")
}
