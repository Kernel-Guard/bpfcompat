package manifest

import "testing"

func TestValidateRejectsUnknownAttachKind(t *testing.T) {
	m := Manifest{
		Programs: []Program{
			{
				Name:    "prog",
				Section: "tracepoint/syscalls/sys_enter_execve",
				Attach: Attach{
					Kind: "unknown-kind",
				},
			},
		},
	}
	if err := Validate(m); err == nil {
		t.Fatal("expected attach kind validation error")
	}
}

func TestValidateAcceptsSimpleManifest(t *testing.T) {
	m := Manifest{
		Name: "simple-pass",
		Programs: []Program{
			{
				Name:    "handle_exec",
				Section: "tracepoint/syscalls/sys_enter_execve",
				Type:    "tracepoint",
				Attach: Attach{
					Kind: "tracepoint",
				},
			},
		},
		RequiredProfiles: []string{"ubuntu-22.04-5.15"},
	}
	if err := Validate(m); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
