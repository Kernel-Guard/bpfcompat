package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteIgnitionSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ign")
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 bpfcompat-run"
	if err := writeIgnitionSeed(path, key+"\n"); err != nil {
		t.Fatalf("writeIgnitionSeed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ignition: %v", err)
	}
	var cfg ignitionConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("ignition config is not valid JSON: %v", err)
	}
	if cfg.Ignition.Version == "" {
		t.Error("ignition.version must be set")
	}
	if len(cfg.Passwd.Users) != 1 || cfg.Passwd.Users[0].Name != "core" {
		t.Fatalf("expected a single core user, got %+v", cfg.Passwd.Users)
	}
	if got := cfg.Passwd.Users[0].SSHAuthorizedKeys; len(got) != 1 || got[0] != key {
		t.Errorf("ssh key = %v, want trimmed %q", got, key)
	}
}

func TestIsCoreOSIgnitionDistro(t *testing.T) {
	for _, d := range []string{"fedora-coreos", "FCOS", "rhcos", "rhel-coreos"} {
		if !isCoreOSIgnitionDistro(Profile{Distro: d}) {
			t.Errorf("%q should be a CoreOS Ignition distro", d)
		}
	}
	for _, d := range []string{"ubuntu", "rhel", "flatcar", "almalinux"} {
		if isCoreOSIgnitionDistro(Profile{Distro: d}) {
			t.Errorf("%q should not be a CoreOS Ignition distro", d)
		}
	}
}

func TestSeedDeliveryForCoreOS(t *testing.T) {
	if got := seedDeliveryForProfile(Profile{Distro: "fedora-coreos"}); got != seedDeliveryIgnition {
		t.Errorf("fedora-coreos seed delivery = %q, want %q", got, seedDeliveryIgnition)
	}
}

func TestBuildQEMUArgsIgnitionFwCfg(t *testing.T) {
	profile := Profile{Distro: "fedora-coreos", Boot: BootConfig{MemoryMB: 2048, CPUs: 2}}
	args := buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/serial.log", 2222, seedDeliveryIgnition, "", "", "/tmp/config.ign")
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !contains(joined, "name=opt/com.coreos/config,file=/tmp/config.ign") {
		t.Fatalf("expected ignition fw_cfg arg, got: %s", joined)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
