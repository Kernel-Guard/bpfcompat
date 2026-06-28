package api

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/marketplace"
)

const testMarketplaceBody = `{
  "action": "purchased",
  "sender": {"login": "octocat", "id": 1, "type": "User"},
  "marketplace_purchase": {
    "account": {"type": "Organization", "id": 18, "login": "acme"},
    "billing_cycle": "monthly",
    "unit_count": 1,
    "plan": {"id": 9, "name": "Team", "monthly_price_in_cents": 4900}
  }
}`

func signMarketplace(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func marketplaceRequest(body, sig, event string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/github/marketplace/webhook", strings.NewReader(body))
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	req.Header.Set("X-GitHub-Delivery", "test-delivery-1")
	return req
}

func TestMarketplaceWebhookValidPurchaseRecorded(t *testing.T) {
	dir := t.TempDir()
	secret := "whsec"
	t.Setenv(envGitHubMarketplaceWebhookSecret, secret)
	s := &Server{cfg: Config{WorkDir: dir}}

	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, marketplaceRequest(testMarketplaceBody, signMarketplace(secret, testMarketplaceBody), "marketplace_purchase"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Ledger written with the parsed summary.
	path := marketplace.LedgerPath(dir)
	f, err := os.Open(path) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("ledger is empty")
	}
	var got marketplace.LedgerRecord
	if err := json.Unmarshal(sc.Bytes(), &got); err != nil {
		t.Fatalf("ledger line not JSON: %v", err)
	}
	if got.Action != "purchased" || got.AccountLogin != "acme" || got.PlanName != "Team" {
		t.Fatalf("ledger record wrong: %+v", got)
	}
}

func TestMarketplaceWebhookRejectsBadSignature(t *testing.T) {
	t.Setenv(envGitHubMarketplaceWebhookSecret, "whsec")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, marketplaceRequest(testMarketplaceBody, signMarketplace("wrong", testMarketplaceBody), "marketplace_purchase"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if _, err := os.Stat(marketplace.LedgerPath(s.cfg.WorkDir)); !os.IsNotExist(err) {
		t.Fatalf("ledger must not be written on bad signature")
	}
}

func TestMarketplaceWebhookSecretNotConfigured(t *testing.T) {
	t.Setenv(envGitHubMarketplaceWebhookSecret, "")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, marketplaceRequest(testMarketplaceBody, "sha256=deadbeef", "marketplace_purchase"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMarketplaceWebhookPing(t *testing.T) {
	secret := "whsec"
	t.Setenv(envGitHubMarketplaceWebhookSecret, secret)
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	body := `{"zen":"Keep it simple."}`
	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, marketplaceRequest(body, signMarketplace(secret, body), "ping"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for ping", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pong") {
		t.Fatalf("ping response missing pong: %s", rec.Body.String())
	}
}

func TestMarketplaceWebhookIgnoresOtherEvents(t *testing.T) {
	secret := "whsec"
	t.Setenv(envGitHubMarketplaceWebhookSecret, secret)
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	body := `{"action":"opened"}`
	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, marketplaceRequest(body, signMarketplace(secret, body), "issues"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for ignored event", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ignored_event") {
		t.Fatalf("expected ignored_event ack: %s", rec.Body.String())
	}
	if _, err := os.Stat(marketplace.LedgerPath(s.cfg.WorkDir)); !os.IsNotExist(err) {
		t.Fatalf("ledger must not be written for ignored events")
	}
}

func TestMarketplaceWebhookMethodNotAllowed(t *testing.T) {
	t.Setenv(envGitHubMarketplaceWebhookSecret, "whsec")
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}

	req := httptest.NewRequest(http.MethodGet, "/github/marketplace/webhook", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleGitHubMarketplaceWebhook(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
