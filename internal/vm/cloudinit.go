package vm

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func writeNoCloudSeed(seedDir, profileID, publicKey string) error {
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		return fmt.Errorf("create seed directory: %w", err)
	}

	userData := strings.TrimSpace(fmt.Sprintf(`
#cloud-config
users:
  - default
ssh_authorized_keys:
  - %s
ssh_pwauth: false
disable_root: true
`, publicKey)) + "\n"

	metaData := strings.TrimSpace(fmt.Sprintf(`
instance-id: bpfcompat-%s
local-hostname: bpfcompat-%s
`, profileID, profileID)) + "\n"

	if err := os.WriteFile(filepath.Join(seedDir, "user-data"), []byte(userData), 0o644); err != nil {
		return fmt.Errorf("write user-data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(seedDir, "meta-data"), []byte(metaData), 0o644); err != nil {
		return fmt.Errorf("write meta-data: %w", err)
	}
	return nil
}

type seedServer struct {
	addr    string
	closeFn func() error
}

func startSeedServer(seedDir string) (seedServer, error) {
	handler := http.FileServer(http.Dir(seedDir))
	server := &http.Server{
		Addr:    "0.0.0.0:0",
		Handler: handler,
	}

	ln, err := listenTCP(server.Addr)
	if err != nil {
		return seedServer{}, err
	}

	go func() {
		_ = server.Serve(ln)
	}()

	return seedServer{
		addr: ln.Addr().String(),
		closeFn: func() error {
			return server.Close()
		},
	}, nil
}

func (s seedServer) seedURL() (string, error) {
	host, port, err := splitHostPort(s.addr)
	if err != nil {
		return "", err
	}
	_ = host
	return fmt.Sprintf("http://10.0.2.2:%s/", port), nil
}
