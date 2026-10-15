package api

import (
	"os"
	"strconv"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
)

// Uploaded artifacts are untrusted: any gzip or tar upload is routed to the
// OCI-archive path, which unpacks it to a temporary directory before the
// eBPF layer is located. The CLI's 8 GiB ceiling is sized for real images
// from the user's own pipeline; for API uploads it let a ~1 MiB gzip expand
// to 1 GiB (x1024) on the host per job. The API therefore bounds the
// expansion by the smaller of an absolute cap and a ratio of the upload size.
//
// Real Inspektor Gadget images are a few MiB (trace_open amd64: one 0.5 MiB
// eBPF layer; trace_exec amd64: 1.6 MiB eBPF + 2.6 MiB wasm layers), stored
// as raw blobs, so an OCI-layout archive expands at most a few times when
// gzip'd and not at all when it is a plain tar. 64x and 512 MiB leave two
// orders of magnitude of headroom for legitimate uploads.
const (
	envMaxArtifactExpandedBytes = "BPFCOMPAT_API_MAX_ARTIFACT_EXPANDED_BYTES"
	// defaultMaxArtifactExpandedBytes is the absolute API cap.
	defaultMaxArtifactExpandedBytes = int64(512 << 20)
	// minArtifactExpandedBytes is both the floor of the ratio cap (so tiny
	// archives are not rejected over tar/gzip framing) and the lowest value
	// the env var can set.
	minArtifactExpandedBytes = int64(1 << 20)
	// apiArtifactExpansionRatio bounds expansion relative to the upload size.
	apiArtifactExpansionRatio = int64(64)
)

// maxArtifactExpandedBytes returns the operator's absolute cap, clamped to
// [1 MiB, CLI ceiling]: the API can never be looser than the CLI.
func maxArtifactExpandedBytes() int64 {
	ceiling := artifact.DefaultOCILimits().MaxArchiveExpandedBytes
	raw := strings.TrimSpace(os.Getenv(envMaxArtifactExpandedBytes))
	if raw == "" {
		return defaultMaxArtifactExpandedBytes
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return defaultMaxArtifactExpandedBytes
	}
	return min(max(value, minArtifactExpandedBytes), ceiling)
}

// apiArtifactOCILimits derives the OCI extraction limits for an upload of
// uploadSize bytes: min(absolute cap, max(64 x upload, 1 MiB)), with the
// eBPF-layer cap never above the CLI's.
func apiArtifactOCILimits(uploadSize int64) artifact.OCILimits {
	absolute := maxArtifactExpandedBytes()
	ratio := minArtifactExpandedBytes
	// Uploads are capped at maxMultipartFormBytes, so this cannot overflow;
	// guard anyway for a future larger cap.
	if uploadSize > 0 && uploadSize <= absolute/apiArtifactExpansionRatio {
		ratio = max(uploadSize*apiArtifactExpansionRatio, minArtifactExpandedBytes)
	} else if uploadSize > 0 {
		ratio = absolute
	}
	limit := min(absolute, ratio)
	return artifact.OCILimits{
		MaxArchiveExpandedBytes: limit,
		MaxArtifactBytes:        min(limit, artifact.DefaultOCILimits().MaxArtifactBytes),
	}
}
