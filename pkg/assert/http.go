// Package assert provides assertion helpers for davlint conformance tests.
// All functions return a descriptive non-nil error on failure.
package assert

import (
	"fmt"
	"strings"

	"github.com/sdobberstein/davlint/pkg/client"
)

// StatusCode asserts that resp.StatusCode equals want.
func StatusCode(resp *client.Response, want int) error {
	if resp.StatusCode != want {
		return fmt.Errorf("status code: got %d, want %d", resp.StatusCode, want)
	}
	return nil
}

// Header asserts that the named response header equals want (case-insensitive comparison).
func Header(resp *client.Response, name, want string) error {
	got := resp.Header.Get(name)
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("header %q: got %q, want %q", name, got, want)
	}
	return nil
}

// HeaderContains asserts that the named response header contains the substring want.
func HeaderContains(resp *client.Response, name, want string) error {
	got := resp.Header.Get(name)
	if !strings.Contains(got, want) {
		return fmt.Errorf("header %q: %q does not contain %q", name, got, want)
	}
	return nil
}
