package vm

import (
	"fmt"
	"os"
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
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		p, err := LoadProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		version, ok := expected[p.ID]
		if !ok {
			t.Errorf("unexpected maintenance profile %s", p.ID)
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
			t.Errorf("missing maintenance profile %s", id)
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
