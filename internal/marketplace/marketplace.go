// Package marketplace handles GitHub Marketplace webhook events
// (marketplace_purchase) for the bpfcompat listing: verifying the delivery
// signature, parsing the payload, and persisting each event to a durable
// append-only ledger for later reconciliation.
//
// This package is transport-agnostic on purpose — signature verification takes
// the raw bytes + header value, and persistence takes a workDir — so the HTTP
// handler in internal/api stays thin and the logic is unit-testable without a
// server. Entitlement/provisioning (what a purchase *grants*) is intentionally
// out of scope here: the ledger is the source of truth a later step consumes.
package marketplace

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EventType is the value GitHub sends in the X-GitHub-Event header for a
// Marketplace purchase event.
const EventType = "marketplace_purchase"

// signaturePrefix is the algorithm tag GitHub prepends to the hex digest in
// the X-Hub-Signature-256 header.
const signaturePrefix = "sha256="

var (
	// ErrSecretNotConfigured indicates no webhook secret is set, so no
	// delivery can be trusted. The handler maps this to 503.
	ErrSecretNotConfigured = errors.New("marketplace webhook secret is not configured")
	// ErrInvalidSignature covers a missing, malformed, or mismatched
	// signature. The handler maps this to 401. The message is deliberately
	// coarse so it cannot be used as a verification oracle.
	ErrInvalidSignature = errors.New("invalid webhook signature")
	// ErrInvalidPayload indicates the body is not a well-formed event.
	ErrInvalidPayload = errors.New("invalid marketplace payload")
)

// KnownActions are the marketplace_purchase actions GitHub documents. Unknown
// actions are still recorded (GitHub may add more) but callers can use this to
// decide whether to act on one.
var KnownActions = map[string]bool{
	"purchased":                true,
	"changed":                  true,
	"cancelled":                true,
	"pending_change":           true,
	"pending_change_cancelled": true,
}

// Account is the buyer (org or user) attached to a purchase, plus the GitHub
// account that triggered the event (sender).
type Account struct {
	Type                     string `json:"type"`
	ID                       int64  `json:"id"`
	Login                    string `json:"login"`
	OrganizationBillingEmail string `json:"organization_billing_email,omitempty"`
}

// Plan is the Marketplace listing plan the buyer is on.
type Plan struct {
	ID                  int64  `json:"id"`
	Name                string `json:"name"`
	MonthlyPriceInCents int64  `json:"monthly_price_in_cents"`
	YearlyPriceInCents  int64  `json:"yearly_price_in_cents"`
	PriceModel          string `json:"price_model"`
}

// Purchase is the marketplace_purchase object (and previous_* on changes).
type Purchase struct {
	Account         Account `json:"account"`
	BillingCycle    string  `json:"billing_cycle"`
	UnitCount       int64   `json:"unit_count"`
	OnFreeTrial     bool    `json:"on_free_trial"`
	FreeTrialEndsOn string  `json:"free_trial_ends_on,omitempty"`
	NextBillingDate string  `json:"next_billing_date,omitempty"`
	Plan            Plan    `json:"plan"`
}

// Event is a parsed marketplace_purchase webhook payload.
type Event struct {
	Action                      string    `json:"action"`
	EffectiveDate               string    `json:"effective_date"`
	Sender                      Account   `json:"sender"`
	MarketplacePurchase         Purchase  `json:"marketplace_purchase"`
	PreviousMarketplacePurchase *Purchase `json:"previous_marketplace_purchase,omitempty"`
}

// VerifySignature checks the X-Hub-Signature-256 header value against an
// HMAC-SHA256 of the exact request body using the shared secret. It is
// constant-time and returns a coarse error so it cannot be used as an oracle.
//
// The body MUST be the raw bytes GitHub sent — verify before any re-encoding.
func VerifySignature(secret, signatureHeader string, body []byte) error {
	if strings.TrimSpace(secret) == "" {
		return ErrSecretNotConfigured
	}
	sig := strings.TrimSpace(signatureHeader)
	if !strings.HasPrefix(sig, signaturePrefix) {
		return fmt.Errorf("%w: missing %q prefix", ErrInvalidSignature, signaturePrefix)
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sig, signaturePrefix))
	if err != nil {
		return fmt.Errorf("%w: signature is not valid hex", ErrInvalidSignature)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	got := mac.Sum(nil)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidSignature
	}
	return nil
}

// ParseEvent decodes a marketplace_purchase payload and validates the minimum
// shape (an action must be present). Unknown actions are accepted; callers can
// consult KnownActions.
func ParseEvent(body []byte) (Event, error) {
	// Decode leniently: GitHub's payload carries many fields we don't model and
	// adds more over time, so we must NOT DisallowUnknownFields here.
	var event Event
	if err := json.Unmarshal(body, &event); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if strings.TrimSpace(event.Action) == "" {
		return Event{}, fmt.Errorf("%w: missing action", ErrInvalidPayload)
	}
	return event, nil
}

// LedgerRecord is one line in the append-only events ledger: a flat summary
// for quick scanning plus the raw payload so nothing is lost for reconciliation.
type LedgerRecord struct {
	ReceivedAt   string          `json:"received_at"`
	DeliveryID   string          `json:"delivery_id,omitempty"`
	EventType    string          `json:"event_type"`
	Action       string          `json:"action"`
	ActionKnown  bool            `json:"action_known"`
	AccountLogin string          `json:"account_login,omitempty"`
	AccountID    int64           `json:"account_id,omitempty"`
	AccountType  string          `json:"account_type,omitempty"`
	PlanID       int64           `json:"plan_id,omitempty"`
	PlanName     string          `json:"plan_name,omitempty"`
	BillingCycle string          `json:"billing_cycle,omitempty"`
	UnitCount    int64           `json:"unit_count,omitempty"`
	OnFreeTrial  bool            `json:"on_free_trial,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`
}

// NewLedgerRecord builds a record from a parsed event, the delivery id, the
// raw payload, and a receive timestamp (RFC3339, passed in so callers control
// the clock and the function stays deterministic in tests).
func NewLedgerRecord(event Event, deliveryID, receivedAt string, raw []byte) LedgerRecord {
	return LedgerRecord{
		ReceivedAt:   receivedAt,
		DeliveryID:   strings.TrimSpace(deliveryID),
		EventType:    EventType,
		Action:       event.Action,
		ActionKnown:  KnownActions[event.Action],
		AccountLogin: event.MarketplacePurchase.Account.Login,
		AccountID:    event.MarketplacePurchase.Account.ID,
		AccountType:  event.MarketplacePurchase.Account.Type,
		PlanID:       event.MarketplacePurchase.Plan.ID,
		PlanName:     event.MarketplacePurchase.Plan.Name,
		BillingCycle: event.MarketplacePurchase.BillingCycle,
		UnitCount:    event.MarketplacePurchase.UnitCount,
		OnFreeTrial:  event.MarketplacePurchase.OnFreeTrial,
		Raw:          append(json.RawMessage(nil), raw...),
	}
}

// LedgerPath returns the JSONL ledger path under workDir.
func LedgerPath(workDir string) string {
	return filepath.Join(filepath.Clean(workDir), "marketplace", "events.jsonl")
}

// AppendLedger appends one record to the events ledger, creating the directory
// as needed. It surfaces Close errors so a failed flush isn't silently lost
// (the handler returns 5xx so GitHub redelivers). Returns the ledger path.
func AppendLedger(workDir string, rec LedgerRecord) (string, error) {
	path := LedgerPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create marketplace ledger directory: %w", err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("marshal marketplace ledger record: %w", err)
	}
	// 0o600: the raw payload can carry an org billing email; keep it owner-only.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("open marketplace ledger: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("append marketplace ledger record: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close marketplace ledger: %w", err)
	}
	return path, nil
}
