package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/registry"
)

// Carbon-aligned badge colours (match the demo/marketing palette).
const (
	badgeGreen  = "#42be65"
	badgeYellow = "#f1c21b"
	badgeRed    = "#fa4d56"
	badgeGray   = "#8d8d8d"
)

// handleBadge serves a shields-style SVG compatibility badge for a run:
//
//	/badge/<run_id>.svg  ->  "compat | 6/8 kernels"
//
// Public and unauthenticated by design (badges are embedded in READMEs and
// rendered by GitHub's camo proxy). Only aggregate counts are exposed — never
// host paths or report internals. An unknown/missing run yields a neutral
// "unknown" badge with HTTP 200, so an embedded image never appears broken.
func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	runID := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/badge/"), ".svg"))

	label := "compat"
	message := "unknown"
	color := badgeGray
	if runID != "" {
		if total, passed, requiredFailed, ok := s.badgeCounts(runID); ok {
			message = fmt.Sprintf("%d/%d kernels", passed, total)
			switch {
			case requiredFailed > 0:
				color = badgeRed
			case passed < total:
				color = badgeYellow
			default:
				color = badgeGreen
			}
		}
	}

	w.Header().Set("Content-Type", "image/svg+xml;charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(renderBadgeSVG(label, message, color)))
}

// badgeCounts loads a run's report and returns (total, passed, requiredFailed).
// ok is false when the run is unknown or unreadable.
func (s *Server) badgeCounts(runID string) (total, passed, requiredFailed int, ok bool) {
	record, err := registry.GetRunRecord(s.cfg.WorkDir, runID)
	if err != nil {
		return 0, 0, 0, false
	}
	raw, err := os.ReadFile(filepath.Clean(record.JSONReportPath))
	if err != nil {
		return 0, 0, 0, false
	}
	var report struct {
		Targets []struct {
			Status   string `json:"status"`
			Required bool   `json:"required"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return 0, 0, 0, false
	}
	for _, t := range report.Targets {
		total++
		switch {
		case strings.EqualFold(t.Status, "pass"):
			passed++
		case t.Required:
			requiredFailed++
		}
	}
	if total == 0 {
		return 0, 0, 0, false
	}
	return total, passed, requiredFailed, true
}

// badgeTextWidth approximates rendered width (px) of Verdana 11 text.
func badgeTextWidth(s string) int {
	// ~6.5px average glyph advance is close enough for a badge.
	w := (len(s)*65 + 5) / 10
	if w < 10 {
		w = 10
	}
	return w
}

func renderBadgeSVG(label, message, color string) string {
	lw := badgeTextWidth(label) + 10
	mw := badgeTextWidth(message) + 10
	total := lw + mw
	el := escapeXML(label)
	em := escapeXML(message)
	// Standard shields "flat" geometry: text is drawn at 10x scale then scaled
	// down 0.1 for crisp rendering, with a shadow text underneath.
	lcx := lw * 5 // label centre, x10
	mcx := (lw + mw/2) * 10
	ltl := (lw - 10) * 10 // textLength, x10
	mtl := (mw - 10) * 10
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+
		`<title>%s: %s</title>`+
		`<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
		`<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>`+
		`<g clip-path="url(#r)">`+
		`<rect width="%d" height="20" fill="#393939"/>`+
		`<rect x="%d" width="%d" height="20" fill="%s"/>`+
		`<rect width="%d" height="20" fill="url(#s)"/>`+
		`</g>`+
		`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">`+
		`<text x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>`+
		`<text x="%d" y="140" transform="scale(.1)" textLength="%d">%s</text>`+
		`<text x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>`+
		`<text x="%d" y="140" transform="scale(.1)" textLength="%d">%s</text>`+
		`</g></svg>`,
		total, el, em,
		el, em,
		total,
		lw,
		lw, mw, color,
		total,
		lcx, ltl, el,
		lcx, ltl, el,
		mcx, mtl, em,
		mcx, mtl, em,
	)
}

func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
