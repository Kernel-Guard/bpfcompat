package api

import (
	"strings"
	"testing"
)

// TestRedactErrorMessageTable pins which parts of an API error message the
// path redactor rewrites: absolute filesystem paths are replaced by
// "[redacted]/<basename>", while ratio-like or slash-separated non-path text
// (queue counters, "and/or") is left intact.
func TestRedactErrorMessageTable(t *testing.T) {
	t.Setenv(envRedactRuntime, "true")
	cases := []struct {
		name    string
		in      string
		want    string
		mustNot []string
	}{
		{
			name:    "existing_case_runtime_fetch",
			in:      "runtime fetch failed: open /home/op/.bpfcompat/runs/abc/artifact: no such file",
			want:    "runtime fetch failed: open [redacted]/artifact: no such file",
			mustNot: []string{"/home/op", ".bpfcompat"},
		},
		{
			name:    "start_of_message",
			in:      "/srv/bpfcompat/work/registry/index.json: permission denied",
			want:    "[redacted]/index.json: permission denied",
			mustNot: []string{"/srv"},
		},
		{
			name:    "single_segment",
			in:      "stat /tmp: permission denied",
			want:    "stat [redacted]/tmp: permission denied",
			mustNot: []string{" /tmp"},
		},
		{
			name:    "quoted",
			in:      `open "/var/lib/bpfcompat/secret.key": denied`,
			want:    `open "[redacted]/secret.key": denied`,
			mustNot: []string{"/var/lib"},
		},
		{
			name:    "after_equals_and_paren",
			in:      "bad config (workdir=/opt/bpfcompat/work)",
			want:    "bad config (workdir=[redacted]/work)",
			mustNot: []string{"/opt/bpfcompat"},
		},
		{
			name:    "two_paths",
			in:      "rename /a/b/c.tmp /a/b/c: exists",
			want:    "rename [redacted]/c.tmp [redacted]/c: exists",
			mustNot: []string{"/a/b"},
		},
		{
			name:    "comma_separated_paths",
			in:      "paths=/a/x,/b/y",
			want:    "paths=[redacted]/x,[redacted]/y",
			mustNot: []string{"/a/x", "/b/y"},
		},
		{
			name:    "file_url_triple_slash",
			in:      "fetch file:///etc/bpfcompat/key.pem failed",
			want:    "fetch file:[redacted]/key.pem failed",
			mustNot: []string{"/etc/bpfcompat"},
		},
		{
			name:    "non_ascii_segment",
			in:      "open /home/jürgen/work/x.o: denied",
			want:    "open [redacted]/x.o: denied",
			mustNot: []string{"/home", "jürgen", "/work"},
		},
		{
			name:    "double_slash_inside",
			in:      "open /srv//bpfcompat/x.o",
			want:    "open [redacted]/x.o",
			mustNot: []string{"/srv", "bpfcompat"},
		},
		{
			name: "validate_queue_full_ratio",
			in:   "validate queue is full (active=1/1 queued=0/20); try again later",
			want: "validate queue is full (active=1/1 queued=0/20); try again later",
		},
		{
			name: "validate_queue_full_ratio_comma",
			in:   "validate queue is full (active=1/1, queued=0/20)",
			want: "validate queue is full (active=1/1, queued=0/20)",
		},
		{
			name: "and_or",
			in:   "tenant and/or project missing",
			want: "tenant and/or project missing",
		},
		{
			name: "fraction_and_rate",
			in:   "rate limit 10/s exceeded, profiles 3/5 passed",
			want: "rate limit 10/s exceeded, profiles 3/5 passed",
		},
		{
			name: "no_paths",
			in:   "artifact_name is required",
			want: "artifact_name is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactErrorMessage(tc.in)
			if got != tc.want {
				t.Fatalf("redactErrorMessage(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
			for _, leak := range tc.mustNot {
				if strings.Contains(got, leak) {
					t.Fatalf("redacted message still contains %q: %q", leak, got)
				}
			}
		})
	}
}
