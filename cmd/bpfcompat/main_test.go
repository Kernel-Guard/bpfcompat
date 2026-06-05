package main

import (
	"reflect"
	"testing"
)

func TestStripHiddenUnsafeHostRunnerFlag(t *testing.T) {
	args := []string{
		"--artifact", "a.o",
		"--unsafe-allow-host-runner=true",
		"--matrix", "m.yaml",
	}

	filtered, allow, err := stripHiddenUnsafeHostRunnerFlag(args)
	if err != nil {
		t.Fatalf("strip hidden flag: %v", err)
	}
	if !allow {
		t.Fatalf("expected hidden allow flag to be true")
	}

	want := []string{"--artifact", "a.o", "--matrix", "m.yaml"}
	if !reflect.DeepEqual(filtered, want) {
		t.Fatalf("unexpected filtered args: got=%v want=%v", filtered, want)
	}
}

func TestStripHiddenUnsafeHostRunnerFlagInvalidBool(t *testing.T) {
	_, _, err := stripHiddenUnsafeHostRunnerFlag([]string{"--unsafe-allow-host-runner=maybe"})
	if err == nil {
		t.Fatalf("expected parse error for invalid hidden bool")
	}
}

func TestSplitCSVUpper(t *testing.T) {
	got := splitCSVUpper("unknown, missing_btf, ,Unsupported_Map_Type")
	want := []string{"UNKNOWN", "MISSING_BTF", "UNSUPPORTED_MAP_TYPE"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected splitCSVUpper result: got=%v want=%v", got, want)
	}
}
