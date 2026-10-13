package vm

import "testing"

func TestParseOSRelease(t *testing.T) {
	for _, tc := range []struct {
		name, content, id, version string
	}{
		{"rhel", "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"8.10 (Ootpa)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"8.10\"\n", "rhel", "8.10"},
		{"oracle", "NAME=\"Oracle Linux Server\"\nID=\"ol\"\nVERSION_ID=\"9.7\"\n", "ol", "9.7"},
		{"ubuntu unquoted id", "ID=ubuntu\nVERSION_ID=\"22.04\"\n", "ubuntu", "22.04"},
		{"single quotes", "ID='debian'\nVERSION_ID='12'\n", "debian", "12"},
		{"id_like is not id", "ID_LIKE=\"rhel centos fedora\"\nID=almalinux\n", "almalinux", ""},
		{"missing", "NAME=Something\n", "", ""},
		{"uppercase is not os-release", "ID=RHEL\n", "", ""},
		{"shell metacharacters are refused", "ID=\"rhel;id\"\nVERSION_ID=\"8$(x)\"\n", "", ""},
		{"empty", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, version := parseOSRelease(tc.content)
			if id != tc.id || version != tc.version {
				t.Fatalf("parseOSRelease = (%q, %q), want (%q, %q)", id, version, tc.id, tc.version)
			}
		})
	}
}
