package assert

import (
	"fmt"
	"strings"
)

// HasProperty asserts that the vCard body contains the given property name
// (case-insensitive), e.g. "FN", "EMAIL".
func HasProperty(body []byte, prop string) error {
	upper := strings.ToUpper(prop)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		lineUpper := strings.ToUpper(line)
		if strings.HasPrefix(lineUpper, upper+":") || strings.HasPrefix(lineUpper, upper+";") {
			return nil
		}
	}
	return fmt.Errorf("vCard property %q not found", prop)
}

// PropertyValue asserts that the vCard body contains the given simple property
// with exactly the given value (case-sensitive, no parameter matching).
func PropertyValue(body []byte, prop, want string) error {
	upper := strings.ToUpper(prop)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToUpper(line), upper+":") {
			got := line[len(prop)+1:]
			if got == want {
				return nil
			}
			return fmt.Errorf("vCard %s: got %q, want %q", prop, got, want)
		}
	}
	return fmt.Errorf("vCard property %q not found", prop)
}

// BodyHas asserts that body contains substr.
func BodyHas(body []byte, substr string) error {
	if !strings.Contains(string(body), substr) {
		return fmt.Errorf("body does not contain %q", substr)
	}
	return nil
}
