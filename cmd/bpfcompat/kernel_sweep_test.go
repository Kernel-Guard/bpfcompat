package main

import "testing"

func TestSweepKernelFamily(t *testing.T) {
	tests := []struct {
		name     string
		release  string
		fallback string
		want     string
	}{
		{
			name:     "Oracle UEK8",
			release:  "6.12.0-204.92.4.4.el9uek.x86_64",
			fallback: "5.15",
			want:     "6.12",
		},
		{
			name:     "Ubuntu",
			release:  "5.15.0-186-generic",
			fallback: "5.15",
			want:     "5.15",
		},
		{
			name:     "malformed",
			release:  "custom-kernel",
			fallback: "custom",
			want:     "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sweepKernelFamily(tt.release, tt.fallback); got != tt.want {
				t.Fatalf("sweepKernelFamily(%q, %q) = %q, want %q", tt.release, tt.fallback, got, tt.want)
			}
		})
	}
}
