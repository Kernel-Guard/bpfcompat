package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A profile's kernel_family is a claim about the kernel series it validates.
// It must be one the profile can actually establish: a pinned install_kernel
// has to belong to that family, and every kernel recorded for the profile in
// vm/kernel-baselines.yaml (the last guest kernel actually observed) has to
// belong to it too. oracle-linux-9-uek7-5.15 requested 5.15 while its image
// booted 6.12 for months; the runner flags that per run, but nothing stopped
// the catalog itself from carrying the false claim.
func TestCatalogKernelFamilyClaimsAreEstablishable(t *testing.T) {
	root := filepath.Join("..", "..")
	paths, err := filepath.Glob(filepath.Join(root, "vm", "profiles", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]Profile{}
	for _, path := range paths {
		p, err := LoadProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		profiles[p.ID] = p
		if p.InstallKernel == "" || strings.TrimSpace(p.KernelFamily) == "" {
			continue
		}
		if match, derivable := schema.KernelFamilyMatch(p.KernelFamily, p.InstallKernel); !derivable || !match {
			t.Errorf("%s: install_kernel %s is not in the declared kernel_family %s", p.ID, p.InstallKernel, p.KernelFamily)
		}
	}

	raw, err := os.ReadFile(filepath.Join(root, "vm", "kernel-baselines.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var baselines struct {
		Baselines []struct {
			Profile string `yaml:"profile"`
			Kernel  string `yaml:"kernel"`
			Crawler *struct {
				ReleasePrefix string `yaml:"release_prefix"`
			} `yaml:"crawler"`
		} `yaml:"baselines"`
	}
	if err := yaml.Unmarshal(raw, &baselines); err != nil {
		t.Fatal(err)
	}
	for _, b := range baselines.Baselines {
		p, ok := profiles[b.Profile]
		if !ok || strings.TrimSpace(p.KernelFamily) == "" {
			continue
		}
		if b.Kernel != "" {
			if match, derivable := schema.KernelFamilyMatch(p.KernelFamily, b.Kernel); !derivable || !match {
				t.Errorf("%s: recorded kernel %s is not in the declared kernel_family %s", b.Profile, b.Kernel, p.KernelFamily)
			}
		}
		// The freshness crawler must track the declared series, or kernel-sweep
		// generates children of another series under this profile's name.
		if b.Crawler != nil && b.Crawler.ReleasePrefix != "" &&
			!strings.HasPrefix(b.Crawler.ReleasePrefix, strings.TrimSpace(p.KernelFamily)+".") {
			t.Errorf("%s: crawler release_prefix %q does not track kernel_family %s", b.Profile, b.Crawler.ReleasePrefix, p.KernelFamily)
		}
	}
}
