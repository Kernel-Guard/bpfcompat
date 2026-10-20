package vm

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The NoCloud seed server is only ever reached by the guest through QEMU
// user-mode networking (slirp), which maps the guest gateway 10.0.2.2 to the
// host's 127.0.0.1. It must therefore listen on IPv4 loopback only, so the
// seed (cloud-config with SSH authorized keys, instance metadata) is not
// exposed on the host's external interfaces while a run is in progress.
func TestStartSeedServerListensOnIPv4LoopbackOnly(t *testing.T) {
	seedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(seedDir, "meta-data"), []byte("instance-id: test\n"), 0o600); err != nil {
		t.Fatalf("write meta-data: %v", err)
	}

	srv, err := startSeedServer(seedDir)
	if err != nil {
		t.Fatalf("startSeedServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.closeFn() })

	host, port, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("split seed server addr %q: %v", srv.addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
		t.Fatalf("seed server must listen on IPv4 loopback, got %q", srv.addr)
	}

	// The guest-facing URL is unchanged: slirp's 10.0.2.2 gateway on the same port.
	url, err := srv.seedURL()
	if err != nil {
		t.Fatalf("seedURL: %v", err)
	}
	if want := "http://10.0.2.2:" + port + "/"; url != want {
		t.Fatalf("seedURL = %q, want %q", url, want)
	}

	// The seed is still served over loopback (what slirp forwards to).
	resp, err := http.Get("http://127.0.0.1:" + port + "/meta-data")
	if err != nil {
		t.Fatalf("GET meta-data over loopback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "instance-id: test") {
		t.Fatalf("unexpected loopback response: status=%d body=%q", resp.StatusCode, body)
	}
}
