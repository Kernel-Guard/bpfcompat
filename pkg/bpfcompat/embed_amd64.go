//go:build hostload && amd64

package bpfcompat

import _ "embed"

//go:embed validators/bpfcompat-validator-amd64
var embeddedValidator []byte
