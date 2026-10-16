package classifier

import "testing"

func TestVerifierProcessedInsnsWordBoundary(t *testing.T) {
	if !verifierProcessedInsnsRe.MatchString("processed 12 insns (limit 1000000)") {
		t.Fatal("verifier summary line must match")
	}
	if verifierProcessedInsnsRe.MatchString("unprocessed 5 insns") {
		t.Fatal("'unprocessed' must not match the verifier summary pattern")
	}
}
