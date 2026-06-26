//go:build hostload && !amd64 && !arm64

package bpfcompat

// No embedded validator is available for this GOARCH. resolveValidator returns
// a clear error when embeddedValidator is empty; callers can still supply one
// via WithValidator.
var embeddedValidator []byte
