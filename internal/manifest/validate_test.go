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

func TestValidateMapFixups(t *testing.T) {
	cases := []struct {
		name    string
		fixup   MapFixup
		wantErr bool
	}{
		{"cpus entries", MapFixup{Name: "auxiliary_maps", MaxEntries: "cpus"}, false},
		{"integer entries", MapFixup{Name: "counter_maps", MaxEntries: "128"}, false},
		{"inner ringbuf only", MapFixup{Name: "ringbuf_maps", InnerRingbufBytes: 8388608}, false},
		{"both settings", MapFixup{Name: "ringbuf_maps", MaxEntries: "cpus", InnerRingbufBytes: 8388608}, false},
		{"missing name", MapFixup{MaxEntries: "cpus"}, true},
		{"shell-unsafe name", MapFixup{Name: "m;rm -rf", MaxEntries: "1"}, true},
		{"no settings", MapFixup{Name: "m"}, true},
		{"zero entries", MapFixup{Name: "m", MaxEntries: "0"}, true},
		{"non-numeric entries", MapFixup{Name: "m", MaxEntries: "lots"}, true},
	}
	for _, tc := range cases {
		err := Validate(Manifest{Maps: []MapFixup{tc.fixup}})
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: unexpected validation error: %v", tc.name, err)
		}
	}

	dup := Manifest{Maps: []MapFixup{
		{Name: "m", MaxEntries: "1"},
		{Name: "m", MaxEntries: "2"},
	}}
	if err := Validate(dup); err == nil {
		t.Error("expected duplicate map fixup error")
	}
}

func TestLoadBytesParsesIntegerMaxEntries(t *testing.T) {
	m, err := LoadBytes([]byte("name: t\nmaps:\n  - name: counter_maps\n    max_entries: 64\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Maps) != 1 || m.Maps[0].MaxEntries != "64" {
		t.Fatalf("unexpected maps: %+v", m.Maps)
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
