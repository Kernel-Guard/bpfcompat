package vm

import (
	"regexp"
	"strings"
)

// osReleaseValue accepts the characters os-release(5) allows in ID and
// VERSION_ID ("a-z, 0-9, '.', '_', '-'"); anything else is not recorded.
var osReleaseValue = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// parseOSRelease extracts ID and VERSION_ID from /etc/os-release content.
// Values are unquoted and must match os-release(5)'s character set;
// malformed or missing values are left empty, which records the guest's
// distribution as unknown rather than guessing it.
func parseOSRelease(content string) (id, versionID string) {
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if !osReleaseValue.MatchString(value) {
			continue
		}
		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			versionID = value
		}
	}
	return id, versionID
}
