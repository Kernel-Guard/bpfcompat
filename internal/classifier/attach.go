package classifier

import (
	"fmt"
	"strings"
)

const (
	enotsupKernel = 524 // kernel-internal ENOTSUPP
	eopnotsupp    = 95

	maxAttachReasonPrograms = 4
	maxAttachReasonBytes    = 1024
)

// classifyAttachFailure attributes an attach failure no further than its
// evidence goes. The errno alone rarely identifies a cause: ENOENT from a
// kprobe attach can be a missing symbol, a missing tracefs, or a blacklisted
// function; EINVAL is returned for dozens of unrelated reasons. Only an
// explicit "operation not supported" from every failing attach is read as an
// unsupported attach type, and even that at medium confidence.
func classifyAttachFailure(failures []AttachFailure) Result {
	if len(failures) > 0 && allNotSupported(failures) {
		return Result{
			Code:       "UNSUPPORTED_ATTACH_TYPE",
			Confidence: "medium",
			Reason: "Attach was refused with \"operation not supported\" after load succeeded: " +
				describeAttachFailures(failures),
			Remediation: "Check whether this kernel/profile offers the attach point, use a supported one, or ship a fallback artifact.",
		}
	}
	reason := "Attach failed after load succeeded; the validator recorded no per-program errno, so the cause is not established."
	if len(failures) > 0 {
		reason = "Attach failed after load succeeded; the errno alone does not establish the cause: " +
			describeAttachFailures(failures)
	}
	return Result{
		Code:        "ATTACH_FAILED",
		Confidence:  "low",
		Reason:      reason,
		Remediation: "Inspect the per-program attach errno and the libbpf log in the report for the failing attach point.",
	}
}

func allNotSupported(failures []AttachFailure) bool {
	for _, f := range failures {
		e := f.Errno
		if e < 0 {
			e = -e
		}
		if e != eopnotsupp && e != enotsupKernel {
			return false
		}
	}
	return true
}

func describeAttachFailures(failures []AttachFailure) string {
	parts := make([]string, 0, maxAttachReasonPrograms+1)
	for i, f := range failures {
		if i == maxAttachReasonPrograms {
			parts = append(parts, fmt.Sprintf("and %d more", len(failures)-i))
			break
		}
		errno := "errno unknown"
		if f.Errno != 0 {
			errno = fmt.Sprintf("errno %d", f.Errno)
		}
		detail := ""
		if strings.TrimSpace(f.Detail) != "" {
			detail = fmt.Sprintf(" %q", clip(f.Detail, 96))
		}
		parts = append(parts, fmt.Sprintf("program %q (%s): %s%s", clip(f.Program, 64), clip(f.Section, 64), errno, detail))
	}
	return clip(strings.Join(parts, "; "), maxAttachReasonBytes)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
