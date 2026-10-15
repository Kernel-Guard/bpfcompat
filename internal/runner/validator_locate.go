package runner

// LocateValidatorBinary reports the validator `bpfcompat test` would stage and
// whether it is dynamically linked (VM-backed runs require a static build). It
// performs the same search as a real run, so diagnostics such as
// `bpfcompat doctor` cannot drift from it.
func LocateValidatorBinary() (path string, dynamic bool, err error) {
	path, err = resolveValidatorBinary()
	if err != nil {
		return "", false, err
	}
	dynamic, err = validatorIsDynamicallyLinked(path)
	return path, dynamic, err
}
