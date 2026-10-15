package runner

import (
	"encoding/json"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// FuzzAttachAccounting feeds arbitrary validator result.json bytes through the
// attach accounting. Whatever the input, accepted accounting is bounded and
// self-consistent, and coverage is one of the documented values.
func FuzzAttachAccounting(f *testing.F) {
	f.Add([]byte(`{"attach":{"mode":"required","status":"pass","attempted":1,"passed":1,"failed":0,"accounting":"v1","effective_mode":"required","program_count":1,"records":1,"selected":1,"not_selected":0,"attachable":1,"not_attachable":0},"load":{"status":"pass"},"discovery":{"programs":[{"name":"a","section":"tracepoint/a/b","autoload":true,"attach_outcome":"attached","attach_operation":"bpf_program__attach","attach_errno":0}]}}`), "required")
	f.Add([]byte(`{"attach":{"mode":"best-effort","status":"warn","attempted":2,"passed":1,"failed":1,"accounting":"v1","effective_mode":"best-effort","program_count":3,"records":3,"selected":3,"not_selected":0,"attachable":2,"not_attachable":1},"load":{"status":"pass"},"discovery":{"programs":[{"name":"a","section":"kprobe/x","autoload":true,"attach_outcome":"attached"},{"name":"b","section":"kprobe/y","autoload":true,"attach_outcome":"failed","attach_errno":-2,"attach_error":"No such file or directory"},{"name":"c","section":"xdp","autoload":true,"attach_outcome":"not_attachable_by_validator"}]}}`), "best-effort")
	f.Add([]byte(`{"attach":{"mode":"required","status":"skipped","attempted":0,"passed":0,"failed":0},"discovery":{"programs":[{"name":"x","section":"xdp","attach_status":"skipped"}]}}`), "required")
	f.Add([]byte(`{"attach":{"accounting":"v1","program_count":-1}}`), "")
	f.Add([]byte(`{}`), "disabled")
	f.Fuzz(func(t *testing.T, data []byte, mode string) {
		var vr validatorResult
		if err := json.Unmarshal(data, &vr); err != nil {
			return
		}
		acc := accountAttach(vr, mode)
		cov := attachCoverage(acc, vr.Load.Status == "pass")
		switch cov {
		case schema.AttachCoverageComplete, schema.AttachCoveragePartial, schema.AttachCoverageNone,
			schema.AttachCoverageEmpty, schema.AttachCoverageNotEvaluated, schema.AttachCoverageUnavailable:
		default:
			t.Fatalf("undocumented coverage %q", cov)
		}
		switch acc.state {
		case schema.AttachAccountingV1:
		case schema.AttachAccountingUnavailable, schema.AttachAccountingInconsistent:
			if len(acc.programs) != 0 {
				t.Fatal("per-program records carried from rejected accounting")
			}
			return
		default:
			t.Fatalf("unknown accounting state %q", acc.state)
		}
		if len(acc.programs) > maxAttachRecords {
			t.Fatal("unbounded records accepted")
		}
		if acc.attempted != acc.passed+acc.failed || acc.selected+acc.notSelected != acc.programCount ||
			acc.attachable+acc.notAttachable != acc.selected {
			t.Fatalf("inconsistent counts accepted: %+v", acc)
		}
		seen := map[string]bool{}
		for i := range acc.programs {
			p := &acc.programs[i]
			if p.Name == "" || len(p.Name) > maxAttachNameBytes || len(p.Detail) > maxAttachDetailBytes || seen[p.Name] {
				t.Fatalf("invalid record accepted: %+v", p)
			}
			seen[p.Name] = true
		}
		// Coverage "complete" is a claim that every selected program was tried.
		if cov == schema.AttachCoverageComplete && acc.attempted != acc.selected {
			t.Fatalf("complete coverage with attempted=%d selected=%d", acc.attempted, acc.selected)
		}
		_ = attachCoverageNote(acc, cov)
		_, _ = requiredAttachGap(acc, []string{"a"})
	})
}
