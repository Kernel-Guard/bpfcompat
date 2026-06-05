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
