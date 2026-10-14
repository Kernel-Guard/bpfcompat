package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/kernel-guard/bpfcompat/internal/artifact"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func TestAPIArtifactOCILimits(t *testing.T) {
	const mib = int64(1 << 20)
	cases := []struct {
		name       string
		env        string
		upload     int64
		wantExpand int64
		wantLayer  int64
	}{
		{"tiny upload gets the 1 MiB floor", "", 1024, 1 * mib, 1 * mib},
		{"ratio binds for a 1 MiB upload", "", 1 * mib, 64 * mib, 64 * mib},
		{"absolute cap binds for a 100 MiB upload", "", 100 * mib, 512 * mib, 512 * mib},
		{"operator lowers the absolute cap", "268435456", 100 * mib, 256 * mib, 256 * mib},
		{"invalid env falls back to default", "lots", 100 * mib, 512 * mib, 512 * mib},
		{"env clamped to the 8 GiB CLI ceiling; layer stays at 512 MiB", "99999999999999", 128 * mib, 8192 * mib, 512 * mib},
		{"env clamped up to the 1 MiB floor", "1", 100 * mib, 1 * mib, 1 * mib},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envMaxArtifactExpandedBytes, tc.env)
			got := apiArtifactOCILimits(tc.upload)
			if got.MaxArchiveExpandedBytes != tc.wantExpand || got.MaxArtifactBytes != tc.wantLayer {
				t.Fatalf("apiArtifactOCILimits(%d) = %+v, want expand=%d layer=%d", tc.upload, got, tc.wantExpand, tc.wantLayer)
			}
		})
	}
}

// TestBuildValidateRunnerConfigSetsUploadBoundOCILimits: the API path always
// hands the runner limits derived from the uploaded size (never the zero
// value that selects the 8 GiB CLI ceiling).
func TestBuildValidateRunnerConfigSetsUploadBoundOCILimits(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	profileID := firstProfileIDForAsyncValidateTest(t)
	s := &Server{cfg: Config{WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: time.Minute}}
	upload := bytes.Repeat([]byte{0x1f, 0x8b}, 1<<19) // 1 MiB
	cfg, status, err := s.buildValidateRunnerConfig(newValidateUploadRequest(t, "/api/validate", profileID, "x.tar.gz", upload))
	if err != nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if cfg.OCILimits.MaxArchiveExpandedBytes != 64<<20 || cfg.OCILimits.MaxArtifactBytes != 64<<20 {
		t.Fatalf("unexpected API OCI limits: %+v", cfg.OCILimits)
	}
}

// TestValidateRatioCapRejectsModestExpansion: a 400x-expanding upload sits far
// below the 512 MiB absolute cap, so only the 64x ratio cap can reject it.
func TestValidateRatioCapRejectsModestExpansion(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(envRedactRuntime, "true")
	t.Setenv("TMPDIR", t.TempDir())
	bomb := gzipZeroTar(t, 4, 8<<20) // 32 MiB of zeros, a few tens of KiB on the wire
	if limits := apiArtifactOCILimits(int64(len(bomb))); limits.MaxArchiveExpandedBytes >= 32<<20 {
		t.Fatalf("test premise: ratio cap %d should be below the 32 MiB payload", limits.MaxArchiveExpandedBytes)
	}
	profileID := firstProfileIDForAsyncValidateTest(t)
	s := &Server{cfg: Config{WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: time.Minute}}
	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateUploadRequest(t, "/api/validate", profileID, "gadget.tar.gz", bomb))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if msg := body["error"]; !bytes.Contains([]byte(msg), []byte("expanded-size limit")) || bytes.Contains([]byte(msg), []byte(os.TempDir())) {
		t.Fatalf("unexpected client error %q", msg)
	}
}

// TestValidateAcceptsLegitimateOCIArchiveUpload: a small gadget image archive
// (`docker save` / tarball format) uploaded through the API still extracts
// under the API limits.
func TestValidateAcceptsLegitimateOCIArchiveUpload(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("bpf"), 4096)...)
	img, err := mutate.AppendLayers(empty.Image, static.NewLayer(elf, types.MediaType("application/vnd.gadget.ebpf.program.v1+binary")))
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := tarball.Write(name.MustParseReference("example.com/gadget:v1"), img, &archive); err != nil {
		t.Fatal(err)
	}

	profileID := firstProfileIDForAsyncValidateTest(t)
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir, DefaultConcurrency: 1, DefaultTimeout: time.Minute}}
	var extracted []byte
	// Stand-in for the runner's OCI step (runner.go), honouring cfg.OCILimits
	// exactly as the real runner does, without booting VMs.
	s.runValidate = func(ctx context.Context, cfg runner.Config) (runner.RunResult, error) {
		path, _, err := artifact.ExtractEBPFFromOCIWithLimits(ctx, cfg.ArtifactPath, t.TempDir(), cfg.OCILimits)
		if err != nil {
			return runner.RunResult{}, err
		}
		extracted, err = os.ReadFile(path)
		if err != nil {
			return runner.RunResult{}, err
		}
		return runner.RunResult{Report: schema.ReportV01{SchemaVersion: "v0.1", Summary: schema.SummaryInfo{Status: "pass"}}}, nil
	}
	rec := httptest.NewRecorder()
	s.handleValidate(rec, newValidateUploadRequest(t, "/api/validate", profileID, "gadget.tar", archive.Bytes()))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(extracted, elf) {
		t.Fatalf("extracted eBPF object mismatch (%d bytes)", len(extracted))
	}
}
