package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadValidatorResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-result.json")
	content := `{
  "schema_version": "validator.v0.2",
  "status": "fail",
  "load": {
    "status": "fail",
    "error_code": -22,
    "error": "Invalid argument"
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := readValidatorResult(path)
	if err != nil {
		t.Fatalf("read validator result: %v", err)
	}
	if result.Status != "fail" {
		t.Fatalf("expected status fail, got %q", result.Status)
	}
	if result.Load.Status != "fail" || result.Load.ErrorCode != -22 {
		t.Fatalf("unexpected load result: %+v", result.Load)
	}
}

func TestReadValidatorResultCapabilities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-result-capabilities.json")
	content := `{
  "schema_version": "validator.v0.2",
  "status": "pass",
  "load": {
    "status": "pass",
    "error_code": 0,
    "error": ""
  },
  "capabilities": {
    "bpftool_available": false,
    "bpftool_probe_ok": false,
    "bpftool_probe_output_path": "",
    "map_types": {
      "ringbuf": {"status":"inconclusive","error_code":-22,"error":"Invalid argument"},
      "perf_event_array": {"status":"supported","error_code":0,"error":""},
      "array": {"status":"supported","error_code":0,"error":""},
      "hash": {"status":"supported","error_code":0,"error":""}
    },
    "program_types": {
      "tracepoint": {"status":"supported","error_code":0,"error":""},
      "kprobe": {"status":"supported","error_code":0,"error":""},
      "tracing": {"status":"inconclusive","error_code":-22,"error":"Invalid argument"},
      "xdp": {"status":"inconclusive","error_code":-22,"error":"Invalid argument"}
    },
    "attach_prereqs": {
      "tracefs": "present",
      "kprobe_events": "missing",
      "tracepoint_events": "present"
    }
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := readValidatorResult(path)
	if err != nil {
		t.Fatalf("read validator result: %v", err)
	}
	if result.Capabilities.MapTypes.Ringbuf.Status != "inconclusive" {
		t.Fatalf("unexpected ringbuf status: %q", result.Capabilities.MapTypes.Ringbuf.Status)
	}
	if result.Capabilities.ProgramTypes.Tracing.Status != "inconclusive" {
		t.Fatalf("unexpected tracing status: %q", result.Capabilities.ProgramTypes.Tracing.Status)
	}
	if result.Capabilities.AttachPrereqs.KprobeEvents != "missing" {
		t.Fatalf("unexpected kprobe_events status: %q", result.Capabilities.AttachPrereqs.KprobeEvents)
	}
}

// TestReadValidatorResultPerProgramLoad covers the validator.v0.3 additions:
// each program record now carries its own isolated load_status / load_errno /
// load_log plus the previously-emitted attach_status / attach_error. The
// decoder must surface these so reports can attribute load failures to a
// specific program × kernel rather than collapsing everything into the
// whole-object load verdict.
func TestReadValidatorResultPerProgramLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-result-per-program.json")
	content := `{
  "schema_version": "validator.v0.3",
  "status": "fail",
  "load": {
    "status": "fail",
    "error_code": -22,
    "error": "Invalid argument"
  },
  "discovery": {
    "program_count": 2,
    "map_count": 0,
    "programs": [
      {
        "name": "handle_execve",
        "section": "lsm/bprm_check_security",
        "attach_status": "skipped",
        "attach_error": "section is not an auto-attach candidate",
        "load_status": "fail",
        "load_errno": -22,
        "load_log": "R1 type=ptr_ expected=scalar"
      },
      {
        "name": "handle_exit",
        "section": "tracepoint/sched/sched_process_exit",
        "attach_status": "pass",
        "attach_error": "",
        "load_status": "pass",
        "load_errno": 0,
        "load_log": ""
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := readValidatorResult(path)
	if err != nil {
		t.Fatalf("read validator result: %v", err)
	}
	if result.SchemaVersion != "validator.v0.3" {
		t.Fatalf("expected schema_version validator.v0.3, got %q", result.SchemaVersion)
	}
	if len(result.Discovery.Programs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(result.Discovery.Programs))
	}
	p0 := result.Discovery.Programs[0]
	if p0.Name != "handle_execve" || p0.LoadStatus != "fail" || p0.LoadErrno != -22 {
		t.Fatalf("unexpected program[0]: %+v", p0)
	}
	if p0.LoadLog == "" {
		t.Fatalf("expected program[0].LoadLog to surface verifier tail")
	}
	if p0.AttachStatus != "skipped" || p0.AttachError == "" {
		t.Fatalf("unexpected program[0] attach state: status=%q error=%q", p0.AttachStatus, p0.AttachError)
	}
	p1 := result.Discovery.Programs[1]
	if p1.LoadStatus != "pass" || p1.LoadErrno != 0 || p1.AttachStatus != "pass" {
		t.Fatalf("unexpected program[1]: %+v", p1)
	}
}

func TestReadValidatorResultFunctional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-result-functional.json")
	content := `{
  "schema_version": "validator.v0.4",
  "status": "fail",
  "load": {"status": "pass"},
  "attach": {"status": "pass"},
  "functional": {
    "status": "fail",
    "tests": [
      {
        "name": "capture-events",
        "required": true,
        "status": "fail",
        "command": "./expect-events.sh",
        "timeout_seconds": 30,
        "expected_exit_code": 0,
        "exit_code": 1,
        "timed_out": false,
        "stdout_tail": "events=0",
        "stderr_tail": "",
        "error": "stdout did not contain expected text"
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := readValidatorResult(path)
	if err != nil {
		t.Fatalf("read validator result: %v", err)
	}
	if result.SchemaVersion != "validator.v0.4" {
		t.Fatalf("expected schema_version validator.v0.4, got %q", result.SchemaVersion)
	}
	if result.Functional.Status != "fail" {
		t.Fatalf("expected functional fail, got %q", result.Functional.Status)
	}
	if len(result.Functional.Tests) != 1 {
		t.Fatalf("expected one functional test, got %d", len(result.Functional.Tests))
	}
	test := result.Functional.Tests[0]
	if test.Name != "capture-events" || !test.Required || test.ExitCode != 1 {
		t.Fatalf("unexpected functional test: %+v", test)
	}
	if test.Error != "stdout did not contain expected text" {
		t.Fatalf("unexpected functional error: %q", test.Error)
	}
}
