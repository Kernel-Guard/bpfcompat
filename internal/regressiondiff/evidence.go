package regressiondiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// maxEvidenceBytes bounds how much of a supplied file is read before anything
// is validated. A release gate consumes CI artifacts that a pull request author
// controls, and os.ReadFile on an attacker-sized file is an OOM before a single
// check runs. The largest report this project has ever produced is ~60 KB (a
// 30-target expanded matrix), so 32 MiB is roughly five hundred times the real
// ceiling: it cannot reject genuine evidence, and it turns "exhaust the runner"
// into "exit 1 with a reason".
const maxEvidenceBytes = 32 << 20

// maxJSONDepth bounds nesting while scanning for duplicate keys. Real reports
// nest five deep. Without a limit, a file of ten thousand "[" characters would
// recurse until the stack died -- a panic is not an acceptable answer to
// malformed evidence, so depth is refused explicitly instead.
const maxJSONDepth = 64

// Evidence is one side's report plus the facts only its raw JSON can answer.
//
// The parsed struct cannot distinguish an absent `required` from `required:
// false`: both deserialize to the Go zero value. That difference decides
// whether a proven regression gates the release, so it is captured here at the
// point where it still exists rather than inferred later.
type Evidence struct {
	Report schema.ReportV01
	Path   string
	Side   string

	// requiredPresent is parallel to Report.Targets: true when that target
	// actually carried a `required` field with a boolean value.
	requiredPresent []bool

	// commandExitCodePresent is true when a command-mode report actually
	// carried `command.expected_exit_code`. The field is a plain int, so an
	// absent one and an explicit 0 are the same Go value, and 0 is the
	// commonest real success contract -- deleting it would otherwise match any
	// baseline expecting success.
	commandExitCodePresent bool
}

// EvidenceFromReport wraps an already-constructed report.
//
// A caller holding a schema.ReportV01 built in Go knows every target's
// `required` value definitely -- absence is a JSON-level concept and cannot
// arise here. Evidence read from a file must come through LoadEvidence, which
// is the only path that sees the raw bytes.
func EvidenceFromReport(r schema.ReportV01, path, side string) Evidence {
	present := make([]bool, len(r.Targets))
	for i := range present {
		present[i] = true
	}
	return Evidence{
		Report: r, Path: path, Side: side, requiredPresent: present,
		// A caller holding the struct stated the value definitely, in command
		// mode or not; absence is a JSON-level concept only.
		commandExitCodePresent: r.Command != nil,
	}
}

// LoadEvidence reads and validates one evidence file.
//
// Everything here is a question about a single report: is this file one
// unambiguous JSON document, and does it contradict itself? Comparison
// questions belong to Build. A file that fails any of it is refused rather than
// partially trusted -- a release gate that guesses which of two values for the
// same field was meant is not a gate.
func LoadEvidence(path, side string) (Evidence, error) {
	blob, err := readBounded(path)
	if err != nil {
		return Evidence{}, err
	}

	// Duplicate keys first: until this passes, no field's value is known, so
	// there is nothing meaningful to validate.
	if err := rejectDuplicateKeys(blob); err != nil {
		return Evidence{}, &InvalidEvidenceError{Side: side, Reason: err.Error()}
	}

	var report schema.ReportV01
	dec := json.NewDecoder(bytes.NewReader(blob))
	if err := dec.Decode(&report); err != nil {
		return Evidence{}, fmt.Errorf("parse report %s: %w", path, err)
	}
	// Decode stops after one JSON value and is happy to leave the rest of the
	// file unread. Evidence with anything after the report -- a second value, a
	// truncated append, stray bytes -- is not evidence we can vouch for, and
	// comparing only its first value would look entirely successful.
	if err := requireEOF(dec); err != nil {
		return Evidence{}, fmt.Errorf("parse report %s: %w", path, err)
	}

	presentRequired, presentExitCode := rawPresence(blob, len(report.Targets))
	ev := Evidence{
		Report:                 report,
		Path:                   path,
		Side:                   side,
		requiredPresent:        presentRequired,
		commandExitCodePresent: presentExitCode,
	}
	if err := Validate(report, side); err != nil {
		return Evidence{}, err
	}
	if err := ev.validatePresence(); err != nil {
		return Evidence{}, err
	}
	return ev, nil
}

// readBounded reads at most maxEvidenceBytes, and reports a file larger than
// that as an error instead of consuming it.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read report %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	blob, err := io.ReadAll(io.LimitReader(f, maxEvidenceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read report %s: %w", path, err)
	}
	if len(blob) > maxEvidenceBytes {
		return nil, fmt.Errorf("read report %s: file is larger than the %d MiB evidence limit; bpfcompat reports are kilobytes, so this is not one",
			path, maxEvidenceBytes>>20)
	}
	return blob, nil
}

// rawPresence recovers the two facts the decoded struct cannot hold: whether
// each target wrote `required`, and whether a command-mode report wrote
// `expected_exit_code`. Both are fields whose absence is indistinguishable from
// a meaningful zero value, and both change a release decision.
//
// Deliberately two named fields rather than a general presence engine: these
// are the only release-decision fields where absence is invisible after
// decoding. Every other one is a pointer, a string that is empty when absent,
// or a slice.
//
// A `null` counts as absent throughout -- it carries no more information than
// omitting the key.
func rawPresence(blob []byte, targets int) (required []bool, commandExitCode bool) {
	var shallow struct {
		Targets []struct {
			Required *bool `json:"required"`
		} `json:"targets"`
		Command *struct {
			ExpectedExitCode *int `json:"expected_exit_code"`
		} `json:"command"`
	}
	required = make([]bool, targets)
	if err := json.Unmarshal(blob, &shallow); err != nil {
		return required, false
	}
	for i := range required {
		if i < len(shallow.Targets) && shallow.Targets[i].Required != nil {
			required[i] = true
		}
	}
	return required, shallow.Command != nil && shallow.Command.ExpectedExitCode != nil
}

// validatePresence refuses evidence that never states a target's requiredness.
//
// `required` decides whether a proven regression gates the release. Absent, it
// deserializes to false, which silently reclassifies a NEW_REGRESSION as an
// optional finding and lets the run exit 0. Deleting a field is not a way to
// discover that an obligation was never required -- it is a way to lose the
// support contract, and the gate says so.
func (e Evidence) validatePresence() error {
	for i := range e.Report.Targets {
		if i < len(e.requiredPresent) && e.requiredPresent[i] {
			continue
		}
		return &InvalidEvidenceError{Side: e.Side, Reason: fmt.Sprintf(
			"target %d (%s) does not record `required`, so whether this obligation gates a release is unknown",
			i, strings.TrimSpace(e.Report.Targets[i].ProfileID))}
	}
	return nil
}

// rejectDuplicateKeys refuses a document containing two keys in one object that
// encoding/json can bind to the same field, at any depth.
//
// encoding/json accepts duplicates and keeps the last value, so
// `"verdict":"INCOMPATIBLE","verdict":"COMPATIBLE"` parses as COMPATIBLE while
// a human reading the file sees a failure. Which value a release decision was
// made from must not depend on a parser's choice, and there is no reading of a
// duplicated field that is evidence of anything. The rule is deliberately
// blanket rather than a list of fields that matter: an exemption list is a
// place for the next contract field to be forgotten.
//
// Exact spelling is not the boundary, because it is not where encoding/json
// draws it. Struct field matching prefers an exact tag match and then falls
// back to a case-insensitive one, so `"verdict"` and `"Verdict"` in the same
// object both bind to Verdict and the later one wins. Measured against the real
// schema types: `verdict`/`Verdict`/`VERDICT`/`vErDiCt` collide, as do
// `profile_id`/`PROFILE_ID`, `required`/`Required`, `summary`/`Summary` and
// `targets`/`Targets`. Removing the underscore (`profileid`) or spelling the Go
// field name (`ProfileID`) does not collide, so no such transformation is
// applied here -- the rule matches the decoder's behaviour and nothing more.
//
// Keys are therefore compared case-folded, exactly as the decoder compares
// them. This does mean two unrelated extension keys differing only in case are
// refused; the alternative is a path-aware model of which objects are structs,
// which is the schema written twice and wrong the first time a field is added.
// A producer emitting `foo` and `Foo` side by side in one object is writing
// evidence whose meaning depends on decoder internals, which is precisely what
// this refuses.
func rejectDuplicateKeys(blob []byte) error {
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.UseNumber()
	err := scanForDuplicateKeys(dec, "", 0)
	if errors.Is(err, errMalformedJSON) {
		// Not this function's finding to report: the real decode below fails on
		// the same bytes and says where. One fault, one error message.
		return nil
	}
	return err
}

// errMalformedJSON stops the scan the moment the token stream stops making
// sense. It must be propagated rather than swallowed: after a token error the
// decoder stays in that error state, and json.Decoder.More keeps answering
// true, so a loop that continues past it never terminates. Fuzzing found
// exactly that -- `"kernel_family_match":ntll` hung the process rather than
// being refused.
var errMalformedJSON = errors.New("malformed JSON")

func scanForDuplicateKeys(dec *json.Decoder, path string, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting deeper than %d is refused; a bpfcompat report is not shaped like this", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return errMalformedJSON
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		// Keyed by the folded name, holding the spelling first seen, so the
		// error can show both spellings of a collision.
		seen := make(map[string]string)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errMalformedJSON
			}
			key, ok := keyTok.(string)
			if !ok {
				return errMalformedJSON
			}
			child := key
			if path != "" {
				child = path + "." + key
			}
			folded := foldKey(key)
			if first, dup := seen[folded]; dup {
				if first == key {
					return fmt.Errorf("the JSON key %q appears twice in the same object; which value the release decision would be made from is ambiguous", child)
				}
				return fmt.Errorf("the JSON keys %q and %q appear in the same object and decode to the same field (field matching is case-insensitive), so which value the release decision would be made from is ambiguous",
					first, key)
			}
			seen[folded] = key
			if err := scanForDuplicateKeys(dec, child, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := scanForDuplicateKeys(dec, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	}
	// Consume the closing delimiter. A truncated document ends the token
	// stream here, which the real decode reports.
	if _, err := dec.Token(); err != nil {
		return errMalformedJSON
	}
	return nil
}

// foldKey normalises a JSON object key the way encoding/json compares one when
// it falls back from an exact match. strings.EqualFold and the decoder's own
// fold both walk Unicode simple folding, so folding to lower case here groups
// exactly the spellings the decoder would treat as one field.
func foldKey(key string) string {
	return strings.ToLower(key)
}
