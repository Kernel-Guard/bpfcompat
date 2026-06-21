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
		{"inner map hash", MapFixup{Name: "kubearmor_visibility", InnerMap: &InnerMapSpec{Type: "hash", KeySize: 4, ValueSize: 4, MaxEntries: 64}}, false},
		{"inner map array no key", MapFixup{Name: "m", InnerMap: &InnerMapSpec{Type: "array", ValueSize: 8, MaxEntries: 1}}, false},
		{"inner map bad type", MapFixup{Name: "m", InnerMap: &InnerMapSpec{Type: "queue", ValueSize: 4, MaxEntries: 1}}, true},
		{"inner map zero value_size", MapFixup{Name: "m", InnerMap: &InnerMapSpec{Type: "hash", KeySize: 4, MaxEntries: 1}}, true},
		{"inner map zero entries", MapFixup{Name: "m", InnerMap: &InnerMapSpec{Type: "hash", KeySize: 4, ValueSize: 4}}, true},
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

func TestValidateProgramVariants(t *testing.T) {
	valid := Manifest{ProgramVariants: []ProgramVariantGroup{{
		Group: "recvmmsg_x",
		Programs: []ProgramVariant{
			{Name: "recvmmsg_x", RequiresHelper: "bpf_loop"},
			{Name: "recvmmsg_old_x"},
		},
	}}}
	if err := Validate(valid); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	numeric := Manifest{ProgramVariants: []ProgramVariantGroup{{
		Group:    "g",
		Programs: []ProgramVariant{{Name: "p", RequiresHelper: "181"}},
	}}}
	if err := Validate(numeric); err != nil {
		t.Fatalf("numeric helper id should validate: %v", err)
	}

	bad := []Manifest{
		{ProgramVariants: []ProgramVariantGroup{{Group: "g"}}},
		{ProgramVariants: []ProgramVariantGroup{{Group: "bad name", Programs: []ProgramVariant{{Name: "p"}}}}},
		{ProgramVariants: []ProgramVariantGroup{{Group: "g", Programs: []ProgramVariant{{Name: "p", RequiresHelper: "no_such_helper"}}}}},
		{ProgramVariants: []ProgramVariantGroup{
			{Group: "g1", Programs: []ProgramVariant{{Name: "p"}}},
			{Group: "g2", Programs: []ProgramVariant{{Name: "p"}}},
		}},
	}
	for i, m := range bad {
		if err := Validate(m); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
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
