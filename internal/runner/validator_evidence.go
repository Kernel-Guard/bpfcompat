package runner

import (
	"encoding/json"
	"fmt"

	"github.com/kernel-guard/bpfcompat/internal/classifier"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// ValidatorEvidence is the runner's reading of one validator result document:
// load and attach evidence, per-program attach accounting, coverage, and the
// target status and classification the matrix engine derives from them.
//
// evaluateValidator is the single place that reading happens. executeTarget
// (the CLI's per-target path) folds it into the report target, and the
// pkg/bpfcompat host-load library exposes it through EvaluateValidatorResult,
// so the two frontends cannot reach different verdicts for the same document.
// What stays frontend-specific is everything around it: on the CLI side the VM
// execution, environment evidence, capability/map-fixup/functional notes,
// report assembly and exit code; on the library side its public Result and
// error values.
type ValidatorEvidence struct {
	// Status is the target status: "pass", "fail", "unsupported" or
	// "infra_error". Verdict is schema.VerdictForStatus(Status).
	Status      string
	Verdict     string
	FailedStage string
	InfraError  string

	ClassificationCode       string
	ClassificationConfidence string
	ClassificationReason     string

	// Validation carries load/attach evidence, including attach_accounting,
	// attach_coverage and the per-program attach records.
	Validation schema.Validation
	// Notes are the load/attach notes the runner attaches to the target:
	// accountingNotes followed by verdictNotes.
	Notes []string

	// The CLI records functional-test notes between the two groups, so it
	// takes them separately.
	accountingNotes []string
	verdictNotes    []string
}

// EvaluateValidatorResult interprets a validator result document exactly as
// the matrix runner does for one target. requestedAttachMode is the
// --attach-mode the validator was run with ("disabled", "best-effort",
// "required"); requiredPrograms are programs that must be attached in
// required mode (the manifest's attach.required programs).
func EvaluateValidatorResult(data []byte, requestedAttachMode string, requiredPrograms []string) (ValidatorEvidence, error) {
	var vr validatorResult
	if err := json.Unmarshal(data, &vr); err != nil {
		return ValidatorEvidence{}, fmt.Errorf("parse validator result: %w", err)
	}
	ev := evaluateValidator(vr, requestedAttachMode, requiredPrograms)
	ev.Verdict = schema.VerdictForStatus(ev.Status)
	return ev, nil
}

func evaluateValidator(vr validatorResult, attachMode string, requiredPrograms []string) ValidatorEvidence {
	ev := ValidatorEvidence{Validation: schema.Validation{
		LoadStatus:      vr.Load.Status,
		LoadErrorCode:   vr.Load.ErrorCode,
		LoadError:       vr.Load.Error,
		AttachMode:      vr.Attach.Mode,
		AttachStatus:    vr.Attach.Status,
		AttachAttempted: vr.Attach.Attempted,
		AttachPassed:    vr.Attach.Passed,
		AttachFailed:    vr.Attach.Failed,
	}}
	acc := accountAttach(vr, attachMode)
	applyAttachAccounting(&ev.Validation, acc, vr.Load.Status == "pass")
	if acc.state == schema.AttachAccountingInconsistent {
		ev.accountingNotes = append(ev.accountingNotes, "attach accounting discarded: "+acc.problem)
	}
	attachStatusNote := func() {
		ev.verdictNotes = append(ev.verdictNotes, fmt.Sprintf(
			"attach status: %s (mode=%s attempted=%d passed=%d failed=%d)",
			vr.Attach.Status, vr.Attach.Mode, vr.Attach.Attempted, vr.Attach.Passed, vr.Attach.Failed))
	}
	classify := func(withAttachFailures bool) {
		in := classifier.Input{
			LoadStatus:         vr.Load.Status,
			LoadErrorCode:      vr.Load.ErrorCode,
			LoadError:          vr.Load.Error,
			AttachStatus:       vr.Attach.Status,
			AttachMode:         vr.Attach.Mode,
			KernelBTFAvailable: vr.BTF.KernelBTFAvailable,
			ArtifactHasBTF:     vr.BTF.ArtifactHasBTF,
			ArtifactHasBTFExt:  vr.BTF.ArtifactHasBTFExt,
			LibbpfLog:          vr.Logs.Libbpf,
			KernelRelease:      vr.Host.Release,
			ProgramSections:    discoveredProgramSections(vr),
			TracingProbeStatus: vr.Capabilities.ProgramTypes.Tracing.Status,
			TracingProbeError:  vr.Capabilities.ProgramTypes.Tracing.ErrorCode,
		}
		if withAttachFailures {
			in.AttachFailures = attachFailuresForClassifier(acc, vr)
			in.AttachFailedTotal = vr.Attach.Failed
		}
		cl := classifier.Classify(in)
		ev.ClassificationCode, ev.ClassificationConfidence, ev.ClassificationReason = cl.Code, cl.Confidence, cl.Reason
		ev.verdictNotes = append(ev.verdictNotes, fmt.Sprintf("classification: %s (%s)", cl.Code, cl.Confidence))
		if cl.Remediation != "" {
			ev.verdictNotes = append(ev.verdictNotes, "remediation: "+cl.Remediation)
		}
	}

	switch {
	case vr.Load.Status == "pass" && vr.Status == "pass":
		ev.Status = "pass"
		if vr.Attach.Attempted > 0 {
			attachStatusNote()
		}
		if note := attachCoverageNote(acc, ev.Validation.AttachCoverage); note != "" {
			ev.verdictNotes = append(ev.verdictNotes, note)
		}
		// Required attach is a claim about every selected program. Loading
		// the object and attaching some of it does not establish it.
		if attachMode == "required" {
			if code, reason := requiredAttachGap(acc, requiredPrograms); code != "" {
				ev.FailedStage = "attach"
				ev.ClassificationCode, ev.ClassificationConfidence, ev.ClassificationReason = code, "high", reason
				ev.verdictNotes = append(ev.verdictNotes, fmt.Sprintf("classification: %s (%s)", code, "high"))
				if code == codeAttachAccountingUnavailable || code == codeAttachAccountingInconsistent {
					ev.Status = "infra_error"
					ev.InfraError = reason
				} else {
					ev.Status = "unsupported"
				}
			}
		}
	case vr.Load.Status == "fail" && loadHitFDLimit(vr.Load.ErrorCode):
		// Every loaded program and link holds a file descriptor; running out
		// of them is the validator process's limit in the guest, not a fact
		// about the artifact (#259). The load evidence above is kept.
		ev.Status = "infra_error"
		ev.FailedStage = "infra"
		ev.InfraError = fmt.Sprintf("the validator process ran out of file descriptors while loading (code=%d %s): a limit of the validator's environment in the guest, not a property of the artifact", vr.Load.ErrorCode, vr.Load.Error)
		ev.verdictNotes = append(ev.verdictNotes, "validator load error: "+ev.InfraError)
	case vr.Load.Status == "fail":
		ev.Status = "fail"
		ev.FailedStage = "load"
		ev.verdictNotes = append(ev.verdictNotes, fmt.Sprintf("validator load error: code=%d message=%s", vr.Load.ErrorCode, vr.Load.Error))
		if vr.Attach.Attempted > 0 || vr.Attach.Status != "" {
			attachStatusNote()
		}
		classify(false)
	case vr.Status == "fail":
		ev.Status = "fail"
		if vr.Functional.Status == "fail" {
			ev.FailedStage = "functional"
			ev.ClassificationCode, ev.ClassificationConfidence = "FUNCTIONAL_TEST_FAILURE", "high"
			ev.ClassificationReason = functionalFailureReason(vr)
			ev.verdictNotes = append(ev.verdictNotes,
				fmt.Sprintf("classification: %s (%s)", ev.ClassificationCode, ev.ClassificationConfidence),
				"remediation: inspect the functional test command output and ship or fix the project-specific integration test assets.",
			)
			break
		}
		if vr.Attach.Status == "fail" {
			ev.FailedStage = "attach"
		} else {
			ev.FailedStage = "validation"
		}
		ev.verdictNotes = append(ev.verdictNotes, "validator reported failure after load phase")
		if vr.Attach.Attempted > 0 || vr.Attach.Status != "" {
			attachStatusNote()
		}
		classify(true)
	default:
		ev.Status = "infra_error"
		ev.FailedStage = "infra"
		ev.InfraError = fmt.Sprintf("unrecognized validator status load=%q status=%q", vr.Load.Status, vr.Status)
	}
	ev.Notes = append(append([]string(nil), ev.accountingNotes...), ev.verdictNotes...)
	return ev
}
