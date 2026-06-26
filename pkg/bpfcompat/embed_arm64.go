//go:build hostload && arm64

package bpfcompat

import _ "embed"

//go:embed validators/bpfcompat-validator-arm64
var embeddedValidator []byte
