package assert

import (
	"fmt"
	"strings"

	"github.com/sdobberstein/davlint/pkg/client"
)

// PropExists asserts that the Multistatus response contains the named property
// with a 200 propstat for the given href.
func PropExists(ms *client.Multistatus, href, ns, local string) error {
	ps, err := findPropStat(ms, href, "HTTP/1.1 200 OK")
	if err != nil {
		return fmt.Errorf("PropExists {%s}%s: %w", ns, local, err)
	}
	if !client.PropInnerXML(ps.Prop.Inner, ns, local) {
		return fmt.Errorf("PropExists: property {%s}%s not found in propstat for <%s>", ns, local, href)
	}
	return nil
}

// findPropStat returns the PropStat for the given href and HTTP status string,
// e.g. "HTTP/1.1 200 OK".
func findPropStat(ms *client.Multistatus, href, status string) (*client.PropStat, error) {
	for i := range ms.Responses {
		r := &ms.Responses[i]
		if r.Href != href {
			continue
		}
		for j := range r.PropStat {
			ps := &r.PropStat[j]
			if strings.TrimSpace(ps.Status) == status {
				return ps, nil
			}
		}
	}
	return nil, fmt.Errorf("href %q not found with status %q in multistatus", href, status)
}
