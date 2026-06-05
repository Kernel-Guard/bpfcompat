package runner

import (
	"debug/elf"
	"fmt"
)

// validatorIsDynamicallyLinked returns true if the ELF binary at path
// has a PT_INTERP program header (indicating dynamic linkage).
// Static binaries have no PT_INTERP entry. Returns an error if the
// file cannot be parsed as ELF.
func validatorIsDynamicallyLinked(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, fmt.Errorf("open validator ELF: %w", err)
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return true, nil
		}
	}
	return false, nil
}
