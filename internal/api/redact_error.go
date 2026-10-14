package api

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error-message path redaction.
//
// The redacted set is a strict superset of the legacy apiAbsolutePathPattern
// (`(/[A-Za-z0-9._-]+)+`) with exactly two exceptions that are never paths:
//
//   - a pure numeric ratio such as "1/1" or "0/20" (digits/digits, not glued
//     to a further "/" or to any [A-Za-z0-9._-] character), and
//   - the literal "and/or" (same boundary rule).
//
// On top of the legacy matches it redacts:
//
//   - whole absolute paths whose segments contain non-ASCII or other
//     characters the legacy class stops at ("/home/jürgen/x.o"), repeated
//     slashes ("/srv//x.o") and "file:///..." forms (apiPathExtraPattern);
//   - the relative prefix glued in front of a match (".bpfcompat/...",
//     "./data/...", "fork/exec"), so a relative workdir name never survives.
//
// Overlapping or touching ranges are merged and each merged range becomes
// "[redacted]/<basename>" ("[redacted]" when the basename is empty, "." or
// "/"), exactly like the legacy replacement.

// apiPathExtraPattern finds an absolute path at a boundary; group 2 is the
// path: "/"-separated segments of any characters except whitespace, quotes
// and common delimiters, plus repeated or trailing slashes.
var apiPathExtraPattern = regexp.MustCompile("(^|[^A-Za-z0-9._-])((?:/+[^\\s/\"'`()<>\\[\\]{},;|]+)+/*)")

// apiRedactionExceptionCandidate finds the candidates for the two exceptions;
// isRedactionException applies the boundary rule.
var apiRedactionExceptionCandidate = regexp.MustCompile(`\d+/\d+|and/or`)

type byteRange struct{ start, end int }

// isLegacyPathByte reports whether c is in the legacy segment class or is "/".
func isLegacyPathByte(c byte) bool {
	return c == '/' || c == '.' || c == '_' || c == '-' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// redactionExceptionRanges returns the protected ratio and "and/or" spans.
func redactionExceptionRanges(message string) []byteRange {
	var out []byteRange
	for _, m := range apiRedactionExceptionCandidate.FindAllStringIndex(message, -1) {
		if m[0] > 0 && isLegacyPathByte(message[m[0]-1]) {
			continue
		}
		if m[1] < len(message) && isLegacyPathByte(message[m[1]]) {
			continue
		}
		out = append(out, byteRange{m[0], m[1]})
	}
	return out
}

func overlapsAny(r byteRange, spans []byteRange) bool {
	for _, s := range spans {
		if r.start < s.end && s.start < r.end {
			return true
		}
	}
	return false
}

// isRelativePrefixRune reports whether r may be part of a relative path
// component glued in front of a redacted range (".bpfcompat", "./data",
// "~", "tenant-1").
func isRelativePrefixRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._~+@-", r)
}

// errorMessageRedactionRanges returns the sorted, merged byte ranges of
// message that redactErrorMessage replaces.
func errorMessageRedactionRanges(message string) []byteRange {
	protected := redactionExceptionRanges(message)
	var ranges []byteRange
	for _, m := range apiAbsolutePathPattern.FindAllStringIndex(message, -1) {
		r := byteRange{m[0], m[1]}
		if !overlapsAny(r, protected) {
			ranges = append(ranges, r)
		}
	}
	for _, m := range apiPathExtraPattern.FindAllStringSubmatchIndex(message, -1) {
		r := byteRange{m[4], m[5]}
		if !overlapsAny(r, protected) {
			ranges = append(ranges, r)
		}
	}
	if len(ranges) == 0 {
		return nil
	}
	// Pull in a relative path component glued in front of each range.
	for i := range ranges {
		for ranges[i].start > 0 {
			r, size := utf8.DecodeLastRuneInString(message[:ranges[i].start])
			if r == utf8.RuneError || !isRelativePrefixRune(r) {
				break
			}
			ranges[i].start -= size
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	merged := []byteRange{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.start <= last.end {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// redactPathRanges replaces each range with "[redacted]/<basename>".
func redactPathRanges(message string, ranges []byteRange) string {
	if len(ranges) == 0 {
		return message
	}
	var out strings.Builder
	last := 0
	for _, r := range ranges {
		out.WriteString(message[last:r.start])
		base := filepath.Base(message[r.start:r.end])
		if base == "" || base == "." || base == "/" {
			out.WriteString("[redacted]")
		} else {
			out.WriteString("[redacted]/" + base)
		}
		last = r.end
	}
	out.WriteString(message[last:])
	return out.String()
}
