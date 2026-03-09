package assert

import (
	"bytes"
	"encoding/xml"
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

// PropHrefContains asserts that the named property in the 207 multistatus contains
// a DAV:href element whose value contains substr. The href parameter is the
// resource path that should appear in the multistatus response element.
func PropHrefContains(ms *client.Multistatus, href, ns, local, substr string) error {
	ps, err := findPropStat(ms, href, "HTTP/1.1 200 OK")
	if err != nil {
		return fmt.Errorf("PropHrefContains {%s}%s: %w", ns, local, err)
	}
	got, err := extractHref(ps.Prop.Inner, ns, local)
	if err != nil {
		return fmt.Errorf("PropHrefContains {%s}%s: %w", ns, local, err)
	}
	if !strings.Contains(got, substr) {
		return fmt.Errorf("PropHrefContains {%s}%s: href %q does not contain %q", ns, local, got, substr)
	}
	return nil
}

// PropHrefValue returns the DAV:href text of the named property in the 207
// multistatus. Use this when you need the actual URL rather than a substring check.
func PropHrefValue(ms *client.Multistatus, href, ns, local string) (string, error) {
	ps, err := findPropStat(ms, href, "HTTP/1.1 200 OK")
	if err != nil {
		return "", fmt.Errorf("PropHrefValue {%s}%s: %w", ns, local, err)
	}
	got, err := extractHref(ps.Prop.Inner, ns, local)
	if err != nil {
		return "", fmt.Errorf("PropHrefValue {%s}%s: %w", ns, local, err)
	}
	return got, nil
}

// extractHref finds the first DAV:href text inside the named property element
// within a raw <prop> inner XML fragment.
func extractHref(inner []byte, ns, local string) (string, error) {
	wrapped := bytes.Join([][]byte{
		[]byte(`<prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`),
		inner,
		[]byte(`</prop>`),
	}, nil)

	dec := xml.NewDecoder(bytes.NewReader(wrapped))
	var (
		depth    int
		inTarget bool
		inHref   bool
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Space == ns && t.Name.Local == local {
				inTarget = true
			}
			if inTarget && depth == 3 && t.Name.Space == "DAV:" && t.Name.Local == "href" {
				inHref = true
			}
		case xml.CharData:
			if inHref {
				return strings.TrimSpace(string(t)), nil
			}
		case xml.EndElement:
			if depth == 3 {
				inHref = false
			}
			if depth == 2 {
				inTarget = false
			}
			depth--
		}
	}
	return "", fmt.Errorf("DAV:href not found in property {%s}%s", ns, local)
}

// NoResponseFor asserts that the multistatus does not contain any response
// for href. Useful for verifying a resource was excluded by a query filter.
func NoResponseFor(ms *client.Multistatus, href string) error {
	for _, r := range ms.Responses {
		if r.Href == href {
			return fmt.Errorf("NoResponseFor: unexpected response entry for href %q", href)
		}
	}
	return nil
}

// ResponseNotFound asserts that the multistatus contains a response for href
// indicating the resource does not exist. RFC 4918 §9.6.1 permits the 404
// status as either a top-level D:status or within a propstat element;
// RFC 6352 §8.7 requires servers to report missing hrefs this way.
func ResponseNotFound(ms *client.Multistatus, href string) error {
	for _, r := range ms.Responses {
		if r.Href != href {
			continue
		}
		if strings.Contains(r.Status, "404") {
			return nil
		}
		for _, ps := range r.PropStat {
			if strings.Contains(ps.Status, "404") {
				return nil
			}
		}
		return fmt.Errorf("ResponseNotFound: href %q present but no 404 status (top-level: %q)", href, r.Status)
	}
	return fmt.Errorf("ResponseNotFound: href %q not found in multistatus", href)
}

// PropTextContains asserts that the text content of the named property in the
// 200 propstat for href contains substr. Unlike BodyHas, this is scoped to a
// specific href and property, making it safe when a multistatus contains
// multiple response entries (e.g. REPORT results).
func PropTextContains(ms *client.Multistatus, href, ns, local, substr string) error {
	ps, err := findPropStat(ms, href, "HTTP/1.1 200 OK")
	if err != nil {
		return fmt.Errorf("PropTextContains {%s}%s: %w", ns, local, err)
	}
	got, err := extractText(ps.Prop.Inner, ns, local)
	if err != nil {
		return fmt.Errorf("PropTextContains {%s}%s: %w", ns, local, err)
	}
	if !strings.Contains(got, substr) {
		return fmt.Errorf("PropTextContains {%s}%s for <%s>: value does not contain %q", ns, local, href, substr)
	}
	return nil
}

// extractText finds the text content of the named element within a raw <prop>
// inner XML fragment. Only direct text children are collected; nested elements
// (if any) are traversed but their tag names are not included in the result.
func extractText(inner []byte, ns, local string) (string, error) {
	wrapped := bytes.Join([][]byte{
		[]byte(`<prop xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`),
		inner,
		[]byte(`</prop>`),
	}, nil)

	dec := xml.NewDecoder(bytes.NewReader(wrapped))
	var (
		depth    int
		inTarget bool
		text     strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Space == ns && t.Name.Local == local {
				inTarget = true
			}
		case xml.CharData:
			if inTarget {
				_, _ = text.Write(t) //nolint:errcheck // strings.Builder.Write never fails
			}
		case xml.EndElement:
			if inTarget && depth == 2 {
				return text.String(), nil
			}
			depth--
		}
	}
	return "", fmt.Errorf("property {%s}%s not found", ns, local)
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
