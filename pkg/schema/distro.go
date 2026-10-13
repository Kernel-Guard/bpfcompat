package schema

import (
	"strconv"
	"strings"
)

// profileDistroOSIDs maps a profile's `distro` to the /etc/os-release ID values
// its guest may report. A profile distro absent from this table has no
// derivable distribution identity: its targets record the observed ID but
// never a match, so they are unknown rather than mismatched.
var profileDistroOSIDs = map[string][]string{
	"almalinux":     {"almalinux"},
	"amazon-linux":  {"amzn"},
	"azurelinux":    {"azurelinux"},
	"centos-stream": {"centos"},
	"debian":        {"debian"},
	"fedora-coreos": {"fedora"},
	"flatcar":       {"flatcar"},
	"opensuse":      {"opensuse-leap"},
	"oracle":        {"ol"},
	"rhcos":         {"rhcos"},
	"rhel":          {"rhel"},
	"rocky":         {"rocky"},
	"sles":          {"sles"},
	"ubuntu":        {"ubuntu"},
}

// DistroMatch reports whether the guest's os-release identity is the
// distribution (and, where both sides carry a numeric major version, the
// major release) the profile names, and whether the question could be
// answered at all.
//
// It is the distribution counterpart of KernelFamilyMatch, and the same rule
// applies: derivable is false when either side carries no identity, and
// callers leave the match unset rather than guess. The os-release ID is
// compared exactly; normalising it is the parser's job.
func DistroMatch(profileDistro, profileVersion, osID, osVersionID string) (match, derivable bool) {
	allowed, known := profileDistroOSIDs[strings.ToLower(strings.TrimSpace(profileDistro))]
	osID = strings.TrimSpace(osID)
	if !known || osID == "" {
		return false, false
	}
	idOK := false
	for _, id := range allowed {
		if osID == id {
			idOK = true
			break
		}
	}
	if !idOK {
		return false, true
	}
	want, wantOK := majorVersion(profileVersion)
	got, gotOK := majorVersion(osVersionID)
	if wantOK && gotOK && want != got {
		return false, true
	}
	return true, true
}

// majorVersion reads the leading numeric component of a release ("8.10" -> 8,
// "22.04" -> 22, "2023" -> 2023). Non-numeric versions ("stable") have none.
func majorVersion(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
