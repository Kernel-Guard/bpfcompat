//go:build !hostload

package bpfcompat

import (
	"context"
	"testing"
)

// The default build (no hostload tag) must keep host loading fenced off.
func TestHostLoadFencedOff(t *testing.T) {
	if _, err := ValidateBeforeLoad(context.Background(), "x.bpf.o"); err != ErrHostLoadNotEnabled {
		t.Errorf("ValidateBeforeLoad err = %v, want ErrHostLoadNotEnabled", err)
	}
	if _, err := ValidateBytes(context.Background(), []byte("x")); err != ErrHostLoadNotEnabled {
		t.Errorf("ValidateBytes err = %v, want ErrHostLoadNotEnabled", err)
	}
}
