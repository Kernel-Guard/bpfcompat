package manifest

import (
	"strings"
	"testing"
)

// The C validator stores each expectation in a 256-byte buffer
// (functional_test.expect_*_contains) and silently truncated longer
// values, so a manifest expectation could quietly check only a prefix.
func TestValidateFunctionalExpectationLength(t *testing.T) {
	atLimit := strings.Repeat("a", 255)
	padded := "  " + atLimit + "  " // trimmed by the plan writer
	over := atLimit + "b"
	cases := []struct {
		name    string
		stdout  string
		stderr  string
		wantErr bool
	}{
		{"stdout at limit", atLimit, "", false},
		{"stderr at limit", "", atLimit, false},
		{"padding trimmed like the plan writer", padded, padded, false},
		{"stdout over limit", over, "", true},
		{"stderr over limit", "", over, true},
		{"multi-byte over limit", strings.Repeat("é", 128), "", true},
	}
	for _, tc := range cases {
		m := Manifest{FunctionalTests: []FunctionalTest{{
			Name:                 "t",
			Command:              "true",
			ExpectStdoutContains: tc.stdout,
			ExpectStderrContains: tc.stderr,
		}}}
		err := Validate(m)
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}
}
