package api

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/marketplace"
)

// handleGitHubMarketplaceWebhook receives GitHub Marketplace purchase events
// for the bpfcompat listing. It is NOT behind the API-key/JWT auth used by the
// rest of the write surface — GitHub can't present those — so the delivery's
// HMAC-SHA256 signature is the sole authenticator. Verified events are appended
// to a durable ledger; provisioning/entitlement is a downstream step that reads
// that ledger.
//
// Status contract (chosen so GitHub redelivers only when it should):
//   - 405 wrong method
//   - 503 webhook secret not configured (endpoint refuses to run open)
//   - 401 missing/invalid signature
//   - 400 malformed payload / missing event header
//   - 200 ping, recorded purchase, or acknowledged-but-ignored other event
//   - 500 persistence failure (GitHub will redeliver)
func (s *Server) handleGitHubMarketplaceWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	secret := strings.TrimSpace(os.Getenv(envGitHubMarketplaceWebhookSecret))
	if secret == "" {
		writeError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("github marketplace webhook is not configured; set %s", envGitHubMarketplaceWebhookSecret))
		return
	}

	// Read the raw body — the signature is computed over the exact bytes GitHub
	// sent, so verify before any re-encoding. MaxBytesReader bounds a hostile
	// sender.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMarketplaceWebhookBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large or unreadable")
		return
	}

	deliveryID := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	eventType := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))

	if err := marketplace.VerifySignature(secret, r.Header.Get("X-Hub-Signature-256"), body); err != nil {
		// Log the precise reason server-side; return a coarse message so the
		// response can't be used as a signature oracle.
		s.log().Warn("rejected github marketplace webhook",
			slog.String("reason", err.Error()),
			slog.String("delivery", deliveryID),
			slog.String("event", eventType),
		)
		if errors.Is(err, marketplace.ErrSecretNotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "github marketplace webhook is not configured")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}

	switch eventType {
	case "":
		writeError(w, http.StatusBadRequest, "missing X-GitHub-Event header")
		return
	case "ping":
		// GitHub sends a ping when the webhook is first configured.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pong": true})
		return
	case marketplace.EventType:
		// fall through to purchase handling
	default:
		// Acknowledge unrelated events with 200 so GitHub doesn't retry them.
		s.log().Info("ignoring non-purchase github marketplace delivery",
			slog.String("event", eventType),
			slog.String("delivery", deliveryID),
		)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ignored_event": eventType})
		return
	}

	event, err := marketplace.ParseEvent(body)
	if err != nil {
		s.log().Warn("malformed github marketplace payload",
			slog.String("error", err.Error()),
			slog.String("delivery", deliveryID),
		)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("parse marketplace event: %v", err))
		return
	}

	rec := marketplace.NewLedgerRecord(event, deliveryID, time.Now().UTC().Format(time.RFC3339), body)
	path, err := marketplace.AppendLedger(s.cfg.WorkDir, rec)
	if err != nil {
		// Return 500 so GitHub redelivers rather than silently dropping a paid
		// purchase event.
		s.log().Error("persist github marketplace event failed",
			slog.String("error", err.Error()),
			slog.String("delivery", deliveryID),
			slog.String("action", event.Action),
		)
		writeError(w, http.StatusInternalServerError, "failed to record marketplace event")
		return
	}

	s.log().Info("github marketplace event recorded",
		slog.String("action", event.Action),
		slog.Bool("action_known", marketplace.KnownActions[event.Action]),
		slog.String("delivery", deliveryID),
		slog.String("account", event.MarketplacePurchase.Account.Login),
		slog.Int64("account_id", event.MarketplacePurchase.Account.ID),
		slog.String("plan", event.MarketplacePurchase.Plan.Name),
		slog.String("ledger", filepath.Base(path)),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"action":  event.Action,
		"account": event.MarketplacePurchase.Account.Login,
		"plan":    event.MarketplacePurchase.Plan.Name,
	})
}
