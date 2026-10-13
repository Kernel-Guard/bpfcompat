package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func centOSImageURL(version string) string {
	return fmt.Sprintf("https://cloud.centos.org/centos/%s-stream/x86_64/images/CentOS-Stream-GenericCloud-%s-latest.x86_64.qcow2", version, version)
}

// This is an offline catalog guard, not evidence that an image downloads or boots.
func TestCentOSProfileSourceURLs(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "vm", "profiles", "centos-stream-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"centos-stream-9-5.14":                 "9",
		"centos-stream-10-6.12":                "10",
		"centos-stream-9-5.14-k5.14.0-725.el9": "9",
		"centos-stream-9-5.14-k5.14.0-729.el9": "9",
		"centos-stream-9-5.14-k5.14.0-731.el9": "9",
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		p, err := LoadProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		version, ok := expected[p.ID]
		if !ok {
			t.Errorf("unexpected CentOS profile %s", p.ID)
			continue
		}
		seen[p.ID] = true
		if p.Version != version || p.Image.SourceURL != centOSImageURL(version) {
			t.Errorf("%s: version=%q URL=%q; want version=%q URL=%q", p.ID, p.Version, p.Image.SourceURL, version, centOSImageURL(version))
		}
		if strings.Contains(p.Image.SourceURL, "GenericCloud-x86_64-") {
			t.Errorf("%s uses obsolete filename", p.ID)
		}
	}
	for id := range expected {
		if !seen[id] {
			t.Errorf("missing CentOS profile %s", id)
		}
	}
}

func TestCentOSGeneratedProfileInheritance(t *testing.T) {
	dir := filepath.Join("..", "..", "vm", "profiles")
	base, err := LoadProfile(filepath.Join(dir, "centos-stream-9-5.14.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := LoadProfile(filepath.Join(dir, "centos-stream-9-5.14-k5.14.0-725.el9.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if derived.InstallKernel != "5.14.0-725.el9.x86_64" || len(derived.KernelPackages) != 3 {
		t.Fatalf("generated kernel installation contract changed: %+v", derived)
	}
	// kernel-sweep copies the base and overrides only these three fields.
	derived.ID = base.ID
	derived.InstallKernel = base.InstallKernel
	derived.KernelPackages = base.KernelPackages
	if !reflect.DeepEqual(derived, base) {
		t.Errorf("generated profile no longer inherits the base profile: got %+v; want %+v", derived, base)
	}
}

func TestCentOSMakefileImageURLs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "CentOS-Stream-GenericCloud-x86_64-") {
		t.Error("Makefile contains obsolete CentOS image filename")
	}
	var recipe strings.Builder
	inRecipe := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "vm-images-extended:") {
			inRecipe = true
			continue
		}
		if !inRecipe {
			continue
		}
		if line != "" && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#") {
			break
		}
		recipe.WriteString(line + "\n")
	}
	for _, version := range []string{"9", "10"} {
		if count := strings.Count(recipe.String(), "\""+centOSImageURL(version)+"\""); count != 1 {
			t.Errorf("vm-images-extended: want exactly one Stream %s URL, got %d", version, count)
		}
	}
	if count := strings.Count(recipe.String(), "https://cloud.centos.org/"); count != 2 {
		t.Errorf("vm-images-extended: want exactly two CentOS URLs, got %d", count)
	}
}

func TestCentOS725SignedPackageURLs(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "vm", "profiles", "centos-stream-9-5.14-k5.14.0-725.el9.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "https://kojihub.stream.centos.org/kojifiles/packages/kernel/5.14.0/725.el9/data/signed/8483c65d/x86_64/"
	want := []string{
		prefix + "kernel-core-5.14.0-725.el9.x86_64.rpm",
		prefix + "kernel-modules-core-5.14.0-725.el9.x86_64.rpm",
		prefix + "kernel-modules-5.14.0-725.el9.x86_64.rpm",
	}
	if !reflect.DeepEqual(p.KernelPackages, want) {
		t.Fatalf("725 packages must use exact signed CentOS build artifacts: got %v; want %v", p.KernelPackages, want)
	}
	cmd := guestKernelInstallCmdRHEL(p.InstallKernel, p.KernelPackages)
	verify := strings.Index(cmd, "sudo rpm --checksig ./pkg*.rpm")
	install := strings.Index(cmd, "sudo dnf -y --setopt=localpkg_gpgcheck=1 install ./pkg*.rpm")
	if verify < 0 || install <= verify || strings.Contains(cmd, "--nogpgcheck") {
		t.Fatalf("signature verification must precede GPG-checked installation: %s", cmd)
	}
	if !strings.Contains(cmd, "/boot/vmlinuz-5.14.0-725.el9.x86_64") {
		t.Fatal("725 installation must select the exact requested kernel")
	}
}

func TestCentOS725KeySelectionAndTransport(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "vm", "profiles", "centos-stream-9-5.14-k5.14.0-725.el9.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := guestKernelInstallCmdRHEL(p.InstallKernel, p.KernelPackages)
	for _, expected := range []string{"RPM-GPG-KEY-CentOS-Official-SHA256", "5af55449d6c9bc594e2e2fb7222374cb25a8ad2d8ea6ce3de894a3201944daa2", "--http1.1 --connect-timeout 15 --max-time 120 --retry 2 --retry-max-time 360"} {
		if !strings.Contains(cmd, expected) {
			t.Errorf("missing pinned key or bounded transport: %s", expected)
		}
	}
	check := strings.Index(cmd, "sha256sum --check --strict")
	importKey := strings.Index(cmd, "sudo rpm --import centos-key.asc")
	verify := strings.Index(cmd, "sudo rpm --checksig")
	if check < 0 || importKey <= check || verify <= importKey {
		t.Fatal("key bytes must be checked before import and package verification")
	}
	for _, forbidden := range []string{"RPM-GPG-KEY-*", "--nogpgcheck", "|| true", "update-crypto-policies"} {
		if strings.Contains(cmd, forbidden) {
			t.Errorf("unsafe key/crypto bypass: %s", forbidden)
		}
	}
	for _, tc := range []struct {
		release string
		urls    []string
	}{
		{"5.14.0-726.el9.x86_64", p.KernelPackages},
		{p.InstallKernel, []string{"https://example.org/kernel.rpm"}},
		{p.InstallKernel, append([]string{"https://example.org/kernel.rpm"}, p.KernelPackages[1:]...)},
	} {
		other := guestKernelInstallCmdRHEL(tc.release, tc.urls)
		if strings.Contains(other, "centos-key.asc") || !strings.Contains(other, "RPM-GPG-KEY-*") {
			t.Fatal("unrelated RHEL installer changed")
		}
	}
}

func TestCentOS725RejectsChangedKeyBeforeImport(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "vm", "profiles", "centos-stream-9-5.14-k5.14.0-725.el9.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// No network, real RPM operations, or host /tmp installer directory.
	for name, script := range map[string]string{
		"curl": "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do if [ \"$1\" = -o ]; then shift; printf tampered >\"$1\"; exit 0; fi; shift; done; exit 1\n",
		"sudo": "#!/bin/sh\nprintf invoked >\"$TEST_SUDO_LOG\"; exit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	command := strings.ReplaceAll(guestKernelInstallCmdRHEL(p.InstallKernel, p.KernelPackages), "/tmp/bpfcompat-kernel", filepath.Join(dir, "kernel"))
	process := exec.Command("bash", "-c", command)
	process.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_SUDO_LOG="+filepath.Join(dir, "sudo.log"))
	output, err := process.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "centos-key.asc: FAILED") {
		t.Fatalf("changed key must fail its real digest check: err=%v output=%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(dir, "sudo.log")); !os.IsNotExist(err) {
		t.Fatal("changed key reached privileged import or installation")
	}
}
