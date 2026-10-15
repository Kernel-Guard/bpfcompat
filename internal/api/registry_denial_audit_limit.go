package api

import (
	"container/list"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
)

// SECURITY (AUTHZ-F3): registry handlers append a *_denied audit event into
// the caller-named tenant/project when the credential check fails. That
// happens before the per-principal rate limit (which needs a principal), so
// an anonymous caller could write unbounded events into any tenant's audit
// log and, because the log rotation is size-capped, evict genuine history.
//
// Denials of callers WITHOUT a valid credential are therefore audited
// through a per-client token bucket plus a global bucket. Over budget, the
// audit write is skipped (counted in bpfcompat_registry_rate_limit_drops_total
// and logged once per suppression run); the HTTP response is unchanged so
// the limiter state is not observable. Denials of authenticated principals
// (a valid credential that lacks scope) are never sampled.
const (
	denialAuditPerClientBurst  = 10
	denialAuditPerClientRefill = 6 * time.Second // 10 per minute sustained
	denialAuditGlobalBurst     = 300
	denialAuditGlobalRefill    = 200 * time.Millisecond // 300 per minute sustained
	denialAuditMaxClients      = 4096
	denialAuditDropAction      = "unauthenticated_denial_audit"
	denialAuditGlobalClientKey = "*global*"
)

var defaultDenialAuditLimiter = newDenialAuditLimiter(time.Now)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) refill(now time.Time, burst int, every time.Duration) {
	if b.last.IsZero() {
		b.tokens = float64(burst)
		b.last = now
		return
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(every)
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}
}

type denialAuditClient struct {
	key         string
	bucket      tokenBucket
	suppressing bool
}

// denialAuditLimiter is an LRU-bounded set of per-client token buckets plus
// one global bucket, so rotating client addresses cannot exceed the global
// budget and the client table never grows past denialAuditMaxClients.
type denialAuditLimiter struct {
	mu                sync.Mutex
	nowFn             func() time.Time
	global            tokenBucket
	globalSuppressing bool
	clients           map[string]*list.Element
	lru               *list.List
}

func newDenialAuditLimiter(nowFn func() time.Time) *denialAuditLimiter {
	return &denialAuditLimiter{
		nowFn:   nowFn,
		clients: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// allow reports whether one more unauthenticated denial from key may be
// written to the audit log, consuming budget when it may.
func (l *denialAuditLimiter) allow(key string) bool {
	now := l.nowFn()
	l.mu.Lock()
	defer l.mu.Unlock()

	var client *denialAuditClient
	if elem, ok := l.clients[key]; ok {
		l.lru.MoveToFront(elem)
		client = elem.Value.(*denialAuditClient)
	} else {
		for l.lru.Len() >= denialAuditMaxClients {
			oldest := l.lru.Back()
			l.lru.Remove(oldest)
			delete(l.clients, oldest.Value.(*denialAuditClient).key)
		}
		client = &denialAuditClient{key: key}
		l.clients[key] = l.lru.PushFront(client)
	}
	client.bucket.refill(now, denialAuditPerClientBurst, denialAuditPerClientRefill)
	l.global.refill(now, denialAuditGlobalBurst, denialAuditGlobalRefill)

	if client.bucket.tokens < 1 {
		l.noteSuppressed(&client.suppressing, key)
		return false
	}
	if l.global.tokens < 1 {
		l.noteSuppressed(&l.globalSuppressing, denialAuditGlobalClientKey)
		return false
	}
	client.bucket.tokens--
	l.global.tokens--
	client.suppressing = false
	l.globalSuppressing = false
	return true
}

func (l *denialAuditLimiter) noteSuppressed(flag *bool, key string) {
	recordRegistryRateLimitDrop(denialAuditDropAction)
	if *flag {
		return
	}
	*flag = true
	slog.Warn("suppressing registry denial audit events for unauthenticated client",
		slog.String("client", sanitizeLogValue(key)))
}

func (l *denialAuditLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}

// denialAuditClientKey derives the limiter key from clientIP (which honors
// X-Forwarded-For only from BPFCOMPAT_API_TRUSTED_PROXIES peers). IPv6
// addresses are grouped by /64, the smallest block a single host commonly
// controls, so address rotation inside one allocation does not mint budget.
func denialAuditClientKey(r *http.Request) string {
	host := clientIP(r)
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// appendRegistryAuthzDenialAudit records the denial produced by a failed
// registry credential check (AuthorizeToken / AuthorizeRead). Only
// ErrUnauthorized (no valid credential presented) is budgeted; every other
// outcome, including ErrForbidden for a valid but out-of-scope credential,
// is audited unconditionally.
func appendRegistryAuthzDenialAudit(r *http.Request, store cloudregistry.Store, event cloudregistry.AuditEvent, authErr error) {
	if errors.Is(authErr, cloudregistry.ErrUnauthorized) && !defaultDenialAuditLimiter.allow(denialAuditClientKey(r)) {
		return
	}
	appendRegistryAuditBestEffort(store, event)
}
