package vm

import (
	"path/filepath"
	"strings"
	"testing"
)

// The v0.3.8 maintenance runtime change (pinned CentOS key + bounded HTTP/1.1
// transport) must apply to EXACTLY the three signed archived 5.14.0-725 RPMs
// declared by the generated sweep profile, and to nothing else. Every near
// miss below must fall back to the unchanged generic RHEL installer.
func TestCentOS725SignedPackageSetIsExact(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "vm", "profiles", "centos-stream-9-5.14-k5.14.0-725.el9.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	exact := p.KernelPackages
	if !isCentOS725SignedPackageSet(p.InstallKernel, exact) {
		t.Fatal("the profile's own signed package set must be recognized")
	}

	clone := func() []string { return append([]string(nil), exact...) }
	replaced := func(i int, from, to string) []string {
		urls := clone()
		urls[i] = strings.Replace(urls[i], from, to, 1)
		return urls
	}
	cases := map[string]struct {
		release string
		urls    []string
	}{
		"reordered packages":      {p.InstallKernel, []string{exact[1], exact[0], exact[2]}},
		"extra fourth package":    {p.InstallKernel, append(clone(), exact[2])},
		"missing package":         {p.InstallKernel, exact[:2]},
		"duplicate package":       {p.InstallKernel, []string{exact[0], exact[0], exact[2]}},
		"unsigned koji path":      {p.InstallKernel, replaced(0, "/data/signed/8483c65d/", "/")},
		"other signing key dir":   {p.InstallKernel, replaced(1, "/signed/8483c65d/", "/signed/deadbeef/")},
		"plain http":              {p.InstallKernel, replaced(2, "https://", "http://")},
		"other host":              {p.InstallKernel, replaced(0, "kojihub.stream.centos.org", "kojihub.example.org")},
		"query suffix":            {p.InstallKernel, replaced(2, ".rpm", ".rpm?x=1")},
		"other architecture":      {p.InstallKernel, replaced(0, "x86_64/kernel-core-5.14.0-725.el9.x86_64", "aarch64/kernel-core-5.14.0-725.el9.aarch64")},
		"neighbouring kernel 726": {"5.14.0-726.el9.x86_64", exact},
		"release without arch":    {"5.14.0-725.el9", exact},
		"empty package list":      {p.InstallKernel, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if isCentOS725SignedPackageSet(tc.release, tc.urls) {
				t.Fatalf("near miss %q must not get the maintenance exception", name)
			}
			cmd := guestKernelInstallCmdRHEL(tc.release, tc.urls)
			if strings.Contains(cmd, "centos-key.asc") || strings.Contains(cmd, "--http1.1") {
				t.Fatalf("near miss %q received the 725-only installer", name)
			}
		})
	}
}
