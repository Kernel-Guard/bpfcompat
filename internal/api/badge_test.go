package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderBadgeSVG(t *testing.T) {
	svg := renderBadgeSVG("compat", "6/8 kernels", badgeGreen)
	for _, want := range []string{"<svg", "compat", "6/8 kernels", badgeGreen, "</svg>"} {
		if !strings.Contains(svg, want) {
			t.Fatalf("badge SVG missing %q:\n%s", want, svg)
		}
	}
	// Special characters in content must be XML-escaped, never raw.
	if strings.Contains(renderBadgeSVG("a<b", "x&y", badgeRed), "a<b") {
		t.Fatalf("badge label was not XML-escaped")
	}
}

// TestHandleBadgeUnknownRun confirms an unknown run yields a valid neutral
// badge with HTTP 200 (so embedded README images never break) rather than an
// error page.
func TestHandleBadgeUnknownRun(t *testing.T) {
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}
	req := httptest.NewRequest(http.MethodGet, "/badge/does-not-exist.svg", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleBadge(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Fatalf("expected svg content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unknown") || !strings.Contains(body, "<svg") {
		t.Fatalf("expected unknown badge svg, got: %s", body)
	}
}

func TestHandleBadgeRejectsNonGet(t *testing.T) {
	s := &Server{cfg: Config{WorkDir: t.TempDir()}}
	req := httptest.NewRequest(http.MethodPost, "/badge/x.svg", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleBadge(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
