package report

import (
	"strings"
	"unicode"
)

// The Markdown renderers interpolate strings an artifact author controls:
// ELF program, section and map names reach the classifier reason and the
// target notes, and the artifact file name reaches the header. GitHub
// sanitises scripts out of a rendered job summary, but a hostile string can
// still close a code span, start a heading or table row, or add links, images
// and bold text that make a failing run read as a passing one. Every value
// that is not a fixed literal of this package goes through one of the
// helpers below.
//
// The escaping is deliberately narrow: it only touches characters that can
// start one of those constructs where they stand, so ordinary report text
// (section names such as "fentry/do_unlinkat", "targets[].verdict",
// "(-22)") renders byte-for-byte as before.

// markdownPlain replaces every control character, and the Unicode line and
// paragraph separators, with a space. A rendered value can then never span
// lines, so it cannot open a block of its own.
func markdownPlain(value string) string {
	clean := true
	for _, r := range value {
		if isMarkdownBreaking(r) {
			clean = false
			break
		}
	}
	if clean {
		return value
	}
	return strings.Map(func(r rune) rune {
		if isMarkdownBreaking(r) {
			return ' '
		}
		return r
	}, value)
}

func isMarkdownBreaking(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

// markdownInline renders value as literal inline Markdown text.
//
//   - '\\' and '*' are always escaped: they would start an escape or emphasis.
//   - '<' is escaped when followed by a letter, '/', '!' or '?', where it
//     could start raw HTML or an autolink.
//   - ']' is escaped when followed by '(', '[' or ':'. That is the only way a
//     bracket pair becomes a link or image here: a reference definition
//     would need its own line, which markdownPlain rules out. A lone
//     "targets[]" is left alone.
//   - '_' is escaped only when it can open emphasis, that is when the
//     character before its run is not a letter or digit. Intraword
//     underscores ("do_unlinkat", "ptr_") cannot, and are left alone.
//   - A leading '#', '>', '-', '+' or ordered-list marker ("1." / "1)") is
//     escaped, because a value is often the whole content of a list item and
//     would otherwise become a heading, quote or nested list.
//   - A backtick run that the value itself closes, around content that needs
//     no escaping, is kept as a code span, so a classifier remediation that
//     quotes `maps:` keeps rendering as code. Any other backtick is escaped,
//     so it can neither pair with a backtick the surrounding template emits
//     later on the line nor wrap hostile text in a span.
func markdownInline(value string) string {
	return escapeInline(value, true)
}

func escapeInline(value string, keepCodeSpans bool) string {
	value = markdownPlain(value)
	runes := []rune(value)
	var b strings.Builder
	b.Grow(len(value) + 8)

	lead := leadingBlockMarker(runes)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '`' {
			n := backtickRun(runes, i)
			if keepCodeSpans {
				if end := closingBacktickRun(runes, i+n, n); end > 0 && isInertCodeSpanContent(runes[i+n:end-n]) {
					b.WriteString(string(runes[i:end]))
					i = end - 1
					continue
				}
			}
			for k := 0; k < n; k++ {
				b.WriteString("\\`")
			}
			i += n - 1
			continue
		}
		switch {
		case i == lead:
			b.WriteByte('\\')
		case r == '\\' || r == '*':
			b.WriteByte('\\')
		case r == '<' && opensTagOrAutolink(runes, i):
			b.WriteByte('\\')
		case r == ']' && i+1 < len(runes) && (runes[i+1] == '(' || runes[i+1] == '[' || runes[i+1] == ':'):
			b.WriteByte('\\')
		case r == '_' && underscoreCanOpen(runes, i):
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isInertCodeSpanContent reports whether content would come out of the
// escaper unchanged, i.e. it holds nothing that could form Markdown even if a
// renderer did not treat the surrounding backticks as a code span. Only such
// spans are kept verbatim; anything else is escaped like prose, so safety
// never rests on code-span precedence alone.
func isInertCodeSpanContent(content []rune) bool {
	s := string(content)
	return escapeInline(s, false) == s
}

// backtickRun returns the length of the backtick run starting at i.
func backtickRun(runes []rune, i int) int {
	n := 0
	for i+n < len(runes) && runes[i+n] == '`' {
		n++
	}
	return n
}

// closingBacktickRun returns the index just past the first run of exactly n
// backticks at or after from, or -1 when there is none.
func closingBacktickRun(runes []rune, from, n int) int {
	for j := from; j < len(runes); {
		if runes[j] != '`' {
			j++
			continue
		}
		m := backtickRun(runes, j)
		if m == n {
			return j + m
		}
		j += m
	}
	return -1
}

// markdownTableText is markdownInline for a table cell, where an unescaped
// '|' would end the cell.
//
// Code spans are not kept here: GFM honours "\|" inside a code span in a
// table, but a backslash right before it cannot be escaped there, so every
// backtick is escaped instead.
func markdownTableText(value string) string {
	return strings.ReplaceAll(escapeInline(value, false), "|", "\\|")
}

// markdownCode renders value as a code span. Backslash escapes do not work
// inside code spans, so a value carrying backticks is fenced with a backtick
// run one longer than its longest run (padded with a space when it starts or
// ends with a backtick), per CommonMark. A value without backticks gets the
// single-backtick span it always had.
func markdownCode(value string) string {
	value = markdownPlain(value)
	longest, run := 0, 0
	for i := 0; i < len(value); i++ {
		if value[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	if longest == 0 {
		return "`" + value + "`"
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		return fence + " " + value + " " + fence
	}
	return fence + value + fence
}

// markdownTableCode is markdownCode for a table cell. GFM splits cells on
// '|' before inline parsing and honours "\|" even inside code spans, but a
// backslash cannot itself be escaped there: "a\|b" would become "a\\|b" and
// end the cell early, leaving the rest of the value to be parsed as
// Markdown. A value containing a backslash is therefore rendered as escaped
// text instead of code.
func markdownTableCode(value string) string {
	value = markdownPlain(value)
	if strings.Contains(value, "\\") {
		return markdownTableText(value)
	}
	return strings.ReplaceAll(markdownCode(value), "|", "\\|")
}

// leadingBlockMarker returns the index of the rune to escape so that runes
// cannot open a block when they start a line or list item, or -1.
func leadingBlockMarker(runes []rune) int {
	i := 0
	for i < len(runes) && runes[i] == ' ' {
		i++
	}
	if i >= len(runes) {
		return -1
	}
	spaceOrEnd := func(k int) bool { return k >= len(runes) || runes[k] == ' ' }
	switch runes[i] {
	case '>':
		// A block quote needs no following space.
		return i
	case '+':
		if spaceOrEnd(i + 1) {
			return i
		}
	case '-':
		// "- x" is a list item and "---" a thematic break.
		if spaceOrEnd(i+1) || runes[i+1] == '-' {
			return i
		}
	case '#':
		k := i
		for k < len(runes) && runes[k] == '#' {
			k++
		}
		if k-i <= 6 && spaceOrEnd(k) {
			return i
		}
	}
	j := i
	for j < len(runes) && j-i < 9 && runes[j] >= '0' && runes[j] <= '9' {
		j++
	}
	if j > i && j < len(runes) && (runes[j] == '.' || runes[j] == ')') &&
		(j+1 == len(runes) || runes[j+1] == ' ') {
		return j
	}
	return -1
}

// opensTagOrAutolink reports whether the '<' at i could start raw HTML or an
// autolink, erring towards yes:
//   - "</", "<!" and "<?" (closing tag, comment or declaration, processing
//     instruction);
//   - '<' + letter, when the name run ([A-Za-z0-9-]) ends the value or is
//     followed by whitespace, '/' or '>' (a tag), or by ':', '+' or '.' (a
//     URI scheme);
//   - '<' + letter with an '@' before the next '>' or space (an email
//     autolink).
//
// Verifier text such as "<byte_off>" is none of these and is left alone.
func opensTagOrAutolink(runes []rune, i int) bool {
	if i+1 >= len(runes) {
		return false
	}
	isASCIILetter := func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
	switch next := runes[i+1]; {
	case next == '/' || next == '!' || next == '?':
		return true
	case !isASCIILetter(next):
		return false
	}
	j := i + 1
	for j < len(runes) && (isASCIILetter(runes[j]) || (runes[j] >= '0' && runes[j] <= '9') || runes[j] == '-') {
		j++
	}
	if j == len(runes) {
		return true
	}
	switch runes[j] {
	case ' ', '/', '>', ':', '+', '.':
		return true
	}
	for k := j; k < len(runes) && runes[k] != '>' && runes[k] != ' '; k++ {
		if runes[k] == '@' {
			return true
		}
	}
	return false
}

// underscoreCanOpen reports whether the '_' at i belongs to a delimiter run
// that is not preceded by a letter or digit. Only such a run can open
// emphasis; one preceded by a letter or digit is right-flanking, and for '_'
// that rules out opening.
func underscoreCanOpen(runes []rune, i int) bool {
	start := i
	for start > 0 && runes[start-1] == '_' {
		start--
	}
	if start == 0 {
		return true
	}
	prev := runes[start-1]
	return !unicode.IsLetter(prev) && !unicode.IsDigit(prev)
}
