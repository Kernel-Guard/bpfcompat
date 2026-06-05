package api

import (
	"errors"
	"net/http"
	"testing"
)

// TestHTTPStatusForErrorMaps every documented category to the documented
// status. A regression here would silently change response codes for
// dozens of handlers once they migrate to writeAPIError, so the map gets
// exhaustive coverage.
func TestHTTPStatusForErrorMaps(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"nil", nil, http.StatusOK},
		{"invalid_input", ErrInvalidInput, http.StatusBadRequest},
		{"unauthorized", ErrUnauthorized, http.StatusUnauthorized},
		{"forbidden", ErrForbidden, http.StatusForbidden},
		{"not_found", ErrNotFound, http.StatusNotFound},
		{"conflict", ErrConflict, http.StatusConflict},
		{"precondition_failed", ErrPreconditionFailed, http.StatusPreconditionFailed},
		{"too_many_requests", ErrTooManyRequests, http.StatusTooManyRequests},
		{"unavailable", ErrUnavailable, http.StatusServiceUnavailable},
		{"transient", ErrTransient, http.StatusBadGateway},
		{"unknown", errors.New("mystery"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpStatusForError(tc.err); got != tc.status {
				t.Fatalf("httpStatusForError(%v) = %d, want %d", tc.err, got, tc.status)
			}
		})
	}
}

// TestWrapAPIErrorPreservesCategory confirms that a wrapped category-tagged
// error still maps to the right status, even when an unrelated wrapper
// (fmt.Errorf %w) sits above it.
func TestWrapAPIErrorPreservesCategory(t *testing.T) {
	inner := errors.New("oops")
	wrapped := wrapAPIError(ErrConflict, "duplicate version", inner)
	if !errors.Is(wrapped, ErrConflict) {
		t.Fatalf("expected wrapped error to be ErrConflict, got %v", wrapped)
	}
	if !errors.Is(wrapped, inner) {
		t.Fatalf("expected wrapped error to unwrap to inner cause")
	}
	if got := httpStatusForError(wrapped); got != http.StatusConflict {
		t.Fatalf("expected 409 for wrapped ErrConflict, got %d", got)
	}
}
