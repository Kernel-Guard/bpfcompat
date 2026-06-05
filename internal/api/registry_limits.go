package api

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	registryRateMaxEnv    = "BPFCOMPAT_REGISTRY_RATE_LIMIT_MAX_REQUESTS"
	registryRateWindowEnv = "BPFCOMPAT_REGISTRY_RATE_LIMIT_WINDOW_SECONDS"
)

var (
	errRegistryRateLimited = errors.New("registry rate limit exceeded")
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
)

type inMemoryRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]rateBucket
	nowFn   func() time.Time
}

type rateBucket struct {
	WindowStart time.Time
	Count       int
}

func newInMemoryRateLimiter(nowFn func() time.Time) *inMemoryRateLimiter {
	return &inMemoryRateLimiter{
		buckets: make(map[string]rateBucket),
		nowFn:   nowFn,
	}
}

func (l *inMemoryRateLimiter) Allow(key string, maxRequests int, window time.Duration) bool {
	if maxRequests <= 0 {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}
	now := l.nowFn().UTC()
	windowStart := now.Truncate(window)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.buckets[key]
	if bucket.WindowStart.IsZero() || !bucket.WindowStart.Equal(windowStart) {
		bucket = rateBucket{WindowStart: windowStart}
	}
	if bucket.Count >= maxRequests {
		l.buckets[key] = bucket
		return false
	}
	bucket.Count++
	l.buckets[key] = bucket
	return true
}

func enforceRegistryRateLimit(subject, tenant, project, action string) error {
	maxRequests, window := registryRateLimitSettings()
	if maxRequests <= 0 {
		return nil
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = "anonymous"
	}
	key := strings.Join([]string{
		"registry",
		subject,
		strings.TrimSpace(tenant),
		strings.TrimSpace(project),
		strings.TrimSpace(action),
	}, "|")

	if defaultRegistryLimiter.Allow(key, maxRequests, window) {
		return nil
	}
	// Surface drop counts to the metrics layer so operators can alert on
	// "tenant X is being throttled" without grepping logs.
	recordRegistryRateLimitDrop(action)
	return fmt.Errorf("%w: max=%d window=%s", errRegistryRateLimited, maxRequests, window)
}

func registryRateLimitSettings() (int, time.Duration) {
	maxRequests := parseEnvIntOrDefault(registryRateMaxEnv, 120)
	windowSeconds := parseEnvIntOrDefault(registryRateWindowEnv, 60)
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	return maxRequests, time.Duration(windowSeconds) * time.Second
}

func parseEnvIntOrDefault(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
