package matrix

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var matrixProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func Validate(m Matrix) error {
	if len(m.Profiles) == 0 {
		return errors.New("matrix must contain at least one profile")
	}

	seen := make(map[string]struct{}, len(m.Profiles))
	for idx, profile := range m.Profiles {
		profileID := strings.TrimSpace(profile.ID)
		if profileID == "" {
			return fmt.Errorf("profiles[%d].id is required", idx)
		}
		if !matrixProfileIDPattern.MatchString(profileID) {
			return fmt.Errorf("profiles[%d].id %q must match %s", idx, profileID, matrixProfileIDPattern.String())
		}
		if _, exists := seen[profileID]; exists {
			return fmt.Errorf("duplicate profile id %q in matrix", profileID)
		}
		seen[profileID] = struct{}{}
	}
	return nil
}
