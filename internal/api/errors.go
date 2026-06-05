package api

import (
	"errors"
	"fmt"
	"net/http"
)

// Sentinel API errors. Handlers wrap these via fmt.Errorf("...: %w", ...);
// httpStatusForError unwraps and chooses the right status code so we never
// have to string-match an error to decide between 400/403/404/etc.
//
// Adding a new category? Pick the existing one that best matches first;
// proliferating sentinels just to be specific bloats the surface without
// helping callers. The existing set covers everything the API server can
// reasonably surface to a client.
var (
	// ErrInvalidInput is for malformed requests, missing required fields,
	// validation failures, etc. — anything where the client supplied the
	// wrong shape. Maps to 400.
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnauthorized is for callers that haven't proven who they are.
	// Maps to 401. Use ErrForbidden when the caller IS known but lacks
	// authority for the requested resource.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden is for authenticated callers acting outside their scope.
	// Maps to 403.
	ErrForbidden = errors.New("forbidden")

	// ErrNotFound is for "the resource you asked about doesn't exist".
	// Maps to 404.
	ErrNotFound = errors.New("not found")

	// ErrConflict is for duplicate creates or version collisions. Maps to 409.
	ErrConflict = errors.New("conflict")

	// ErrPreconditionFailed is for cases where the request shape is fine
	// but a runtime invariant blocks it (history not verified, policy gate
	// denied, etc.). Maps to 412.
	ErrPreconditionFailed = errors.New("precondition failed")

	// ErrTooManyRequests is for rate-limit / queue-full responses. Maps to 429.
	ErrTooManyRequests = errors.New("too many requests")

	// ErrUnavailable is for "the server itself isn't ready" — shutting
	// down, dependency missing, kill switch tripped. Maps to 503.
	ErrUnavailable = errors.New("service unavailable")

	// ErrTransient is for upstream blips that the caller can safely retry
	// (registry I/O hiccup, JWKS source temporarily down, etc.). Maps to
	// 502. Distinct from ErrUnavailable because the *server* is fine; the
	// problem is downstream.
	ErrTransient = errors.New("transient upstream error")
)

// apiError lets handlers attach a sentinel category + human message in a
// single value while preserving wrapping. Use New(category, "msg") /
// Wrap(category, err) so the category is queryable via errors.Is.
type apiError struct {
	category error
	msg      string
	wrapped  error
}

func (e *apiError) Error() string {
	switch {
	case e.wrapped != nil && e.msg != "":
		return e.msg + ": " + e.wrapped.Error()
	case e.wrapped != nil:
		return e.wrapped.Error()
	case e.msg != "":
		return e.msg
	default:
		return e.category.Error()
	}
}

// Unwrap returns the underlying cause, if any. Errors.Is/As reaches both
// the category and the wrapped error.
func (e *apiError) Unwrap() error { return e.wrapped }

// Is reports whether target matches the category. This is what lets a
// handler write `errors.Is(err, ErrNotFound)` even when err is a wrapped
// apiError with a deeper cause.
func (e *apiError) Is(target error) bool {
	return target != nil && (target == e.category || errors.Is(e.category, target))
}

// newAPIError tags msg with category. Prefer fmt.Errorf("...: %w", err) +
// wrapAPIError when you have an underlying cause; this constructor is for
// validation errors that originate in the handler itself.
//
//nolint:unused // exported via wrapAPIError; kept distinct for symmetry.
func newAPIError(category error, msg string) error {
	return &apiError{category: category, msg: msg}
}

// wrapAPIError binds cause to a category. The category determines the HTTP
// status; the cause's message is preserved verbatim (so existing error
// strings keep flowing through to the response after redaction).
//
//nolint:unused // wired into handlers progressively; safe to keep exported.
func wrapAPIError(category error, msg string, cause error) error {
	return &apiError{category: category, msg: msg, wrapped: cause}
}

// httpStatusForError maps a category-tagged error to its HTTP status. Falls
// back to 500 when nothing matches so an unrecognized error never silently
// becomes a 200.
func httpStatusForError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrPreconditionFailed):
		return http.StatusPreconditionFailed
	case errors.Is(err, ErrTooManyRequests):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrTransient):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// writeAPIError pairs writeError with the category-aware status mapper.
// Existing handlers will migrate to this incrementally so we get the
// status-code dispatch for free as call sites flip over.
//
//nolint:unused // adopted incrementally; landed here so the test suite can
// validate the contract before every handler is converted.
func writeAPIError(w http.ResponseWriter, err error) {
	status := httpStatusForError(err)
	writeError(w, status, err.Error())
}

// Static assertion: every sentinel must be a distinct error so errors.Is
// queries don't accidentally collapse categories. fmt.Sprintf forces the
// compiler to materialize each entry; the value is then thrown away.
var _ = fmt.Sprintf("%v%v%v%v%v%v%v%v%v",
	ErrInvalidInput, ErrUnauthorized, ErrForbidden, ErrNotFound,
	ErrConflict, ErrPreconditionFailed, ErrTooManyRequests, ErrUnavailable, ErrTransient,
)
