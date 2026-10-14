package report

import "testing"

func TestMarkdownCodeFencesBackticks(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "`plain`"},
		{"a`b", "``a`b``"},
		{"a``b`", "``` a``b` ```"},
		{"`x", "`` `x ``"},
		{"line\nbreak\x1b", "`line break `"},
	} {
		if got := markdownCode(tc.in); got != tc.want {
			t.Errorf("markdownCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMarkdownTableCodeKeepsCellsIntact(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"5.15.0-186-generic", "`5.15.0-186-generic`"},
		{"a|b", "`a\\|b`"},
		// A backslash cannot be escaped inside a code span, and "\\|" would
		// end the cell early, so such values drop to escaped prose.
		{`a\|b`, `a\\\|b`},
		// Escaped prose in a cell never keeps a code span.
		{"x`y\\|z`", "x\\`y\\\\\\|z\\`"},
	} {
		if got := markdownTableCode(tc.in); got != tc.want {
			t.Errorf("markdownTableCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMarkdownInlineEscapesOnlyWhatCanForm(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Ordinary report prose is left byte-identical.
		{"Program section \"fentry/do_unlinkat\" requires support (5.5).", "Program section \"fentry/do_unlinkat\" requires support (5.5)."},
		{"Check targets[].verdict, infra_error.", "Check targets[].verdict, infra_error."},
		{"0: R1 type=ptr_ expected=scalar", "0: R1 type=ptr_ expected=scalar"},
		{"exit status 1 (expected 0)", "exit status 1 (expected 0)"},
		// Constructs that could spoof the rendered report are neutralised.
		{"[a](http://e)", `[a\](http://e)`},
		{"![i](http://e)", `![i\](http://e)`},
		{"[a][b]", `[a\][b]`},
		{"**PASS**", `\*\*PASS\*\*`},
		{"_PASS_", `\_PASS_`},
		{"kprobe/__x64_sys", `kprobe/\_\_x64_sys`},
		{"<img src=x>", `\<img src=x>`},
		{"<unnamed>", `\<unnamed>`},
		{"</b>", `\</b>`},
		{"<https://e>", `\<https://e>`},
		{"<a_b@evil.example>", `\<a_b@evil.example>`},
		{"relocation <byte_off> [5]", "relocation <byte_off> [5]"},
		{"kernel < 5.8", "kernel < 5.8"},
		// A code span the value closes itself stays a code span (its content
		// is literal); an unclosed backtick is escaped.
		{"under `maps:` in the manifest", "under `maps:` in the manifest"},
		{"`[a](http://e)`", "\\`[a\\](http://e)\\`"},
		{"`<img src=x>`", "\\`\\<img src=x>\\`"},
		{"a`b [c](http://e)", "a\\`b [c\\](http://e)"},
		{"a``b`c", "a\\`\\`b\\`c"},
		{`back\slash`, `back\\slash`},
		{"# heading", `\# heading`},
		{"- item", `\- item`},
		{"+ item", `\+ item`},
		{"> quote", `\> quote`},
		{"1. item", `1\. item`},
		{"12) item", `12\) item`},
		{"a\nb\r\x1bc", "a b  c"},
		{"a\u2028b\u0085c", "a b c"},
	} {
		if got := markdownInline(tc.in); got != tc.want {
			t.Errorf("markdownInline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
