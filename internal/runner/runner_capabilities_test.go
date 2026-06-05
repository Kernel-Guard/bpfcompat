package runner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilityProbeNotes(t *testing.T) {
	vr := validatorResult{}
	vr.Capabilities.BPFToolAvailable = false
	vr.Capabilities.AttachPrereqs.Tracefs = "missing"
	vr.Capabilities.MapTypes.Ringbuf = probeStatus{
		Status:    "unsupported",
		ErrorCode: -95,
		Error:     "Operation not supported",
	}
	vr.Capabilities.ProgramTypes.Tracing = probeStatus{
		Status:    "inconclusive",
		ErrorCode: -22,
		Error:     "Invalid argument",
	}

	notes := capabilityProbeNotes(vr)
	if len(notes) == 0 {
		t.Fatalf("expected capability notes, got none")
	}

	assertContains := func(substr string) {
		t.Helper()
		for _, n := range notes {
			if n == substr {
				return
			}
		}
		t.Fatalf("expected note %q not found in %#v", substr, notes)
	}

	assertContains("bpftool unavailable; used custom capability probes")
	assertContains("attach prereq missing: tracefs")
	assertContains("capability map.ringbuf: unsupported (code=-95 err=Operation not supported)")
}

func TestCapabilityProbeNotesSkipInconclusive(t *testing.T) {
	vr := validatorResult{}
	vr.Capabilities.MapTypes.Ringbuf = probeStatus{
		Status:    "inconclusive",
		ErrorCode: -22,
		Error:     "Invalid argument",
	}

	notes := capabilityProbeNotes(vr)
	for _, note := range notes {
		if strings.Contains(note, "capability map.ringbuf") {
			t.Fatalf("expected inconclusive map note to be skipped, got %q", note)
		}
	}
}
func TestPerProgramLoadNotesIncludesVerifierTail(t *testing.T) {
	vr := validatorResultFromJSON(t, `{"discovery":{"programs":[{"name":"handle_execve","section":"lsm/bprm_check_security","load_status":"fail","load_errno":-22,"load_log":"0: R1 type=ptr_ expected=scalar\nprocessed 8 insns"},{"name":"handle_exit","section":"tracepoint/sched/sched_process_exit","load_status":"pass","load_errno":0}]}}`)

	notes := perProgramLoadNotes(vr)
	assertNoteContains(t, notes, "program load failure: name=handle_execve section=lsm/bprm_check_security errno=-22")
	assertNoteContains(t, notes, "program load verifier tail (handle_execve): 0: R1 type=ptr_ expected=scalar processed 8 insns")
	for _, note := range notes {
		if strings.Contains(note, "handle_exit") {
			t.Fatalf("expected passing program to be omitted, got notes %#v", notes)
		}
	}
}

func TestPerProgramLoadNotesTruncatesLargeFailureSets(t *testing.T) {
	vr := validatorResultFromJSON(t, `{"discovery":{"programs":[{"name":"p0","load_status":"fail"},{"name":"p1","load_status":"fail"},{"name":"p2","load_status":"fail"},{"name":"p3","load_status":"fail"},{"name":"p4","load_status":"fail"},{"name":"p5","load_status":"fail"},{"name":"p6","load_status":"fail"},{"name":"p7","load_status":"fail"},{"name":"p8","load_status":"fail"}]}}`)

	notes := perProgramLoadNotes(vr)
	assertNoteContains(t, notes, "program load failure: name=p0")
	assertNoteContains(t, notes, "program load failure details truncated: 1 additional program(s)")
	for _, note := range notes {
		if strings.Contains(note, "name=p8") {
			t.Fatalf("expected ninth program detail to be truncated, got notes %#v", notes)
		}
	}
}

func validatorResultFromJSON(t *testing.T, content string) validatorResult {
	t.Helper()
	var vr validatorResult
	if err := json.Unmarshal([]byte(content), &vr); err != nil {
		t.Fatalf("unmarshal validator result: %v", err)
	}
	return vr
}

func assertNoteContains(t *testing.T, notes []string, want string) {
	t.Helper()
	for _, note := range notes {
		if strings.Contains(note, want) {
			return
		}
	}
	t.Fatalf("expected note containing %q, got %#v", want, notes)
}
