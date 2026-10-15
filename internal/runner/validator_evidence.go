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
// It exists so that callers that run the validator themselves (the
// pkg/bpfcompat host-load library) reach the same verdict as the CLI from the
// same document. It is built from the same helpers executeTarget uses
// (accountAttach, applyAttachAccounting, requiredAttachGap,
// attachCoverageNote, attachFailuresForClassifier, classifier.Classify);
// validator_evidence_test.go checks it against executeTarget fixture by
// fixture so the two cannot drift silently.
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
	// Notes are the load/attach notes the runner would attach to the target.
	Notes []string
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
		ev.Notes = append(ev.Notes, "attach accounting discarded: "+acc.problem)
	}
	attachStatusNote := func() {
		ev.Notes = append(ev.Notes, fmt.Sprintf(
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
		ev.Notes = append(ev.Notes, fmt.Sprintf("classification: %s (%s)", cl.Code, cl.Confidence))
		if cl.Remediation != "" {
			ev.Notes = append(ev.Notes, "remediation: "+cl.Remediation)
		}
	}

	switch {
	case vr.Load.Status == "pass" && vr.Status == "pass":
		ev.Status = "pass"
		if vr.Attach.Attempted > 0 {
			attachStatusNote()
		}
		if note := attachCoverageNote(acc, ev.Validation.AttachCoverage); note != "" {
			ev.Notes = append(ev.Notes, note)
		}
		if attachMode == "required" {
			if code, reason := requiredAttachGap(acc, requiredPrograms); code != "" {
				ev.FailedStage = "attach"
				ev.ClassificationCode, ev.ClassificationConfidence, ev.ClassificationReason = code, "high", reason
				ev.Notes = append(ev.Notes, fmt.Sprintf("classification: %s (%s)", code, "high"))
				if code == codeAttachAccountingUnavailable || code == codeAttachAccountingInconsistent {
					ev.Status = "infra_error"
					ev.InfraError = reason
				} else {
					ev.Status = "unsupported"
				}
			}
		}
	case vr.Load.Status == "fail":
		ev.Status = "fail"
		ev.FailedStage = "load"
		ev.Notes = append(ev.Notes, fmt.Sprintf("validator load error: code=%d message=%s", vr.Load.ErrorCode, vr.Load.Error))
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
			ev.Notes = append(ev.Notes, fmt.Sprintf("classification: %s (%s)", ev.ClassificationCode, ev.ClassificationConfidence))
			break
		}
		if vr.Attach.Status == "fail" {
			ev.FailedStage = "attach"
		} else {
			ev.FailedStage = "validation"
		}
		ev.Notes = append(ev.Notes, "validator reported failure after load phase")
		if vr.Attach.Attempted > 0 || vr.Attach.Status != "" {
			attachStatusNote()
		}
		classify(true)
	default:
		ev.Status = "infra_error"
		ev.FailedStage = "infra"
		ev.InfraError = fmt.Sprintf("unrecognized validator status load=%q status=%q", vr.Load.Status, vr.Status)
	}
	return ev
}
