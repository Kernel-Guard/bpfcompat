package marketplace

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const samplePurchase = `{
  "action": "purchased",
  "effective_date": "2026-06-28T00:00:00+00:00",
  "sender": {"login": "octocat", "id": 1, "type": "User"},
  "marketplace_purchase": {
    "account": {"type": "Organization", "id": 18, "login": "acme", "organization_billing_email": "billing@acme.example"},
    "billing_cycle": "monthly",
    "unit_count": 1,
    "on_free_trial": false,
    "next_billing_date": "2026-07-28T00:00:00+00:00",
    "plan": {"id": 9, "name": "Team", "monthly_price_in_cents": 4900, "yearly_price_in_cents": 49900, "price_model": "flat-rate"}
  }
}`

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(samplePurchase)
	good := sign(secret, samplePurchase)

	if err := VerifySignature(secret, good, body); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	cases := []struct {
		name string
		sec  string
		sig  string
		body []byte
		want error
	}{
		{"no secret", "", good, body, ErrSecretNotConfigured},
		{"missing prefix", secret, hex.EncodeToString([]byte("x")), body, ErrInvalidSignature},
		{"not hex", secret, signaturePrefix + "zz", body, ErrInvalidSignature},
		{"wrong secret", "other", good, body, ErrInvalidSignature},
		{"tampered body", secret, good, []byte(samplePurchase + " "), ErrInvalidSignature},
		{"empty sig", secret, "", body, ErrInvalidSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignature(tc.sec, tc.sig, tc.body)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want errors.Is %v", err, tc.want)
			}
		})
	}
}

func TestParseEvent(t *testing.T) {
	event, err := ParseEvent([]byte(samplePurchase))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if event.Action != "purchased" {
		t.Fatalf("action = %q, want purchased", event.Action)
	}
	if !KnownActions[event.Action] {
		t.Fatalf("purchased should be a known action")
	}
	if got := event.MarketplacePurchase.Account.Login; got != "acme" {
		t.Fatalf("account login = %q, want acme", got)
	}
	if got := event.MarketplacePurchase.Plan.Name; got != "Team" {
		t.Fatalf("plan name = %q, want Team", got)
	}
	if got := event.MarketplacePurchase.Plan.MonthlyPriceInCents; got != 4900 {
		t.Fatalf("monthly price = %d, want 4900", got)
	}
}

func TestParseEventRejectsMissingAction(t *testing.T) {
	if _, err := ParseEvent([]byte(`{"marketplace_purchase":{}}`)); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
	if _, err := ParseEvent([]byte(`not json`)); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for bad json, got %v", err)
	}
}

func TestParseEventAcceptsUnknownAction(t *testing.T) {
	event, err := ParseEvent([]byte(`{"action":"some_new_action","marketplace_purchase":{}}`))
	if err != nil {
		t.Fatalf("unknown action should still parse: %v", err)
	}
	if KnownActions[event.Action] {
		t.Fatalf("some_new_action should not be known")
	}
}

func TestAppendLedger(t *testing.T) {
	dir := t.TempDir()
	event, err := ParseEvent([]byte(samplePurchase))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rec := NewLedgerRecord(event, "delivery-123", "2026-06-28T12:00:00Z", []byte(samplePurchase))

	path, err := AppendLedger(dir, rec)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if path != LedgerPath(dir) {
		t.Fatalf("path = %q, want %q", path, LedgerPath(dir))
	}

	// Owner-only perms because the raw payload can carry a billing email.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat ledger: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ledger perm = %o, want 600", perm)
	}

	// Append a second record and verify both lines are valid JSON.
	if _, err := AppendLedger(dir, rec); err != nil {
		t.Fatalf("second append: %v", err)
	}
	f, err := os.Open(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer f.Close()
	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var got LedgerRecord
		if err := json.Unmarshal(sc.Bytes(), &got); err != nil {
			t.Fatalf("ledger line %d not valid JSON: %v", lines, err)
		}
		if got.DeliveryID != "delivery-123" || got.PlanName != "Team" || !got.ActionKnown {
			t.Fatalf("ledger line %d fields wrong: %+v", lines, got)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("ledger has %d lines, want 2", lines)
	}
}
