package schema

import (
	"encoding/json"
	"testing"
)

func TestReportV01OmitsOptionalExecutionProvenance(t *testing.T) {
	data, err := json.Marshal(ReportV01{SchemaVersion: "v0.1"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["command"]; ok {
		t.Fatal("command must be omitted outside command mode")
	}
	if _, ok := decoded["validator"]; ok {
		t.Fatal("validator must be omitted outside artifact mode")
	}
}

func TestReportV01SerializesExecutionProvenance(t *testing.T) {
	report := ReportV01{
		SchemaVersion: "v0.1",
		Artifact: Artifact{
			Source: "ghcr.io/example/gadget@sha256:abc",
		},
		Command: &CommandInfo{
			InvocationSHA256: "invocation",
			ExpectedExitCode: 2,
			Binary: &BinaryIdentity{
				BaseName:  "loader",
				SHA256:    "loader-sha",
				SizeBytes: 42,
			},
		},
		Validator: &BinaryIdentity{
			BaseName:  "validator",
			SHA256:    "validator-sha",
			SizeBytes: 84,
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Artifact  Artifact        `json:"artifact"`
		Command   *CommandInfo    `json:"command"`
		Validator *BinaryIdentity `json:"validator"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Command == nil || decoded.Command.Binary == nil {
		t.Fatal("command provenance was not serialized")
	}
	if decoded.Command.ExpectedExitCode != 2 || decoded.Command.Binary.SHA256 != "loader-sha" {
		t.Fatalf("unexpected command provenance: %+v", decoded.Command)
	}
	if decoded.Validator == nil || decoded.Validator.SHA256 != "validator-sha" {
		t.Fatalf("unexpected validator provenance: %+v", decoded.Validator)
	}
	if decoded.Artifact.Source != "ghcr.io/example/gadget@sha256:abc" {
		t.Fatalf("unexpected artifact source: %q", decoded.Artifact.Source)
	}
}
