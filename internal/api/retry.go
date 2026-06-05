package api

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"time"
)

// httpRetryOptions tunes the retry loop. A nil-zero options value means
// "no retries" — callers must opt in explicitly. We deliberately keep this
// small: a senior reviewer should be able to read the entire backoff policy
// without scrolling.
type httpRetryOptions struct {
	// MaxAttempts is the total number of attempts (initial + retries). Set
	// to 3 by callers that want bounded retry; 1 disables retry entirely.
	MaxAttempts int
	// BaseDelay is the starting backoff. Each retry waits BaseDelay * 2^n
	// up to MaxDelay, plus jitter.
	BaseDelay time.Duration
	// MaxDelay caps the per-attempt sleep so a long-running retry doesn't
	// outlive the caller's context.
	MaxDelay time.Duration
}

// defaultHTTPRetry is the policy used for JWKS / OIDC discovery fetches —
// upstream blips of a few seconds are common and should never propagate as
// 5xx to a user-facing request.
var defaultHTTPRetry = httpRetryOptions{
	MaxAttempts: 3,
	BaseDelay:   200 * time.Millisecond,
	MaxDelay:    2 * time.Second,
}

// httpDoWithRetry performs req with bounded retry on transient failures:
//   - any error returned by client.Do (TCP RST, DNS timeout, etc.)
//   - HTTP 5xx
//   - HTTP 429 (the upstream is asking us to slow down)
//
// 4xx other than 429 short-circuits with no retry — those are caller bugs,
// not infrastructure blips, and retrying would just hide the problem.
// The request body must be re-readable across attempts; for JWKS/OIDC
// (GET, no body) this is trivially fine.
//
// Each retry waits cryptographically-jittered exponential backoff so a
// thundering herd of clients doesn't all retry on the same wall-clock tick.
func httpDoWithRetry(ctx context.Context, client *http.Client, req *http.Request, opts httpRetryOptions) (*http.Response, error) {
	if opts.MaxAttempts < 1 {
		opts.MaxAttempts = 1
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = 100 * time.Millisecond
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = time.Second
	}

	var lastErr error
	for attempt := 0; attempt < opts.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffWithJitter(attempt-1, opts.BaseDelay, opts.MaxDelay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Clone the request so the original is reusable across attempts —
		// http.Client mutates req on send (e.g. setting Host).
		attemptReq := req.Clone(ctx)
		resp, err := client.Do(attemptReq)
		if err != nil {
			lastErr = err
			if !isRetryableErr(err) {
				return nil, err
			}
			continue
		}
		if shouldRetryStatus(resp.StatusCode) {
			// Drain and close so the connection can return to the pool;
			// otherwise the next attempt opens a fresh socket every time.
			drainAndClose(resp.Body)
			lastErr = errors.New(resp.Status)
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("retry attempts exhausted")
	}
	return nil, lastErr
}

func shouldRetryStatus(code int) bool {
	if code == http.StatusTooManyRequests {
		return true
	}
	return code >= 500 && code < 600
}

func isRetryableErr(err error) bool {
	// Anything that's not a hard semantic error is worth one more shot.
	// We're deliberately permissive here because the JWKS/OIDC path is
	// idempotent and the worst case is a few extra ms of latency.
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// backoffWithJitter returns BaseDelay * 2^attempt, capped at MaxDelay, with
// uniform [0, base] jitter. Using crypto/rand for the jitter is overkill
// but it sidesteps math/rand's process-wide seed quirks and keeps the
// import surface aligned with the rest of the package.
func backoffWithJitter(attempt int, base, maximum time.Duration) time.Duration {
	exp := base
	for i := 0; i < attempt && exp < maximum; i++ {
		exp *= 2
	}
	if exp > maximum {
		exp = maximum
	}
	jitter := readUniformDuration(base)
	total := exp + jitter
	if total > maximum {
		total = maximum
	}
	return total
}

// readUniformDuration returns a duration in [0, max). Random failures fall
// back to half of max which keeps the retry loop bounded.
func readUniformDuration(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	var n uint64
	if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &n); err != nil {
		return maximum / 2
	}
	return time.Duration(n % uint64(maximum))
}

// drainAndClose discards the response body so HTTP keep-alive can recycle
// the underlying connection on the next attempt. Errors are intentionally
// ignored — we already know the response was retryable.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
