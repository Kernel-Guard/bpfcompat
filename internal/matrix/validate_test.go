package matrix

import "testing"

func TestValidateRejectsDuplicateProfiles(t *testing.T) {
	m := Matrix{
		Profiles: []MatrixProfile{
			{ID: "ubuntu-22.04-5.15"},
			{ID: "ubuntu-22.04-5.15"},
		},
	}
	if err := Validate(m); err == nil {
		t.Fatal("expected duplicate profile id error")
	}
}

func TestValidateAcceptsMinimalMatrix(t *testing.T) {
	m := Matrix{
		Name: "mvp",
		Profiles: []MatrixProfile{
			{ID: "ubuntu-22.04-5.15"},
		},
	}
	if err := Validate(m); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateRejectsInvalidProfileID(t *testing.T) {
	m := Matrix{
		Profiles: []MatrixProfile{
			{ID: "../ubuntu-22.04-5.15"},
		},
	}
	if err := Validate(m); err == nil {
		t.Fatal("expected invalid profile id error")
	}
}

func TestQuickMatrix(t *testing.T) {
	m := Quick()
	if m.Name != "quick" {
		t.Fatalf("expected name quick, got %q", m.Name)
	}
	if len(m.Profiles) == 0 {
		t.Fatal("quick matrix must have profiles")
	}
	for _, p := range m.Profiles {
		if !p.RequiredBool() {
			t.Errorf("quick profile %q should default to required", p.ID)
		}
	}
	if err := Validate(m); err != nil {
		t.Fatalf("quick matrix must validate: %v", err)
	}
}
