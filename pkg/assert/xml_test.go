package assert_test

import (
	"testing"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
)

// buildMS constructs a Multistatus with a single 200 propstat for href
// containing the given inner XML fragment.
func buildMS(href, innerXML string) *client.Multistatus {
	return &client.Multistatus{
		Responses: []client.MSResponse{{
			Href: href,
			PropStat: []client.PropStat{{
				Prop:   client.RawProp{Inner: []byte(innerXML)},
				Status: "HTTP/1.1 200 OK",
			}},
		}},
	}
}

func TestPropExists_Pass_DAVNamespace(t *testing.T) {
	ms := buildMS("/alice/", `<D:displayname xmlns:D="DAV:">Alice</D:displayname>`)
	if err := assert.PropExists(ms, "/alice/", "DAV:", "displayname"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropExists_Pass_CardDAVNamespace(t *testing.T) {
	ms := buildMS("/alice/", `<C:addressbook-home-set xmlns:C="urn:ietf:params:xml:ns:carddav"/>`)
	if err := assert.PropExists(ms, "/alice/", "urn:ietf:params:xml:ns:carddav", "addressbook-home-set"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropExists_HrefNotFound(t *testing.T) {
	ms := buildMS("/alice/", `<D:displayname xmlns:D="DAV:">Alice</D:displayname>`)
	if err := assert.PropExists(ms, "/bob/", "DAV:", "displayname"); err == nil {
		t.Error("expected error when href not in multistatus")
	}
}

func TestPropExists_PropertyNotPresent(t *testing.T) {
	ms := buildMS("/alice/", `<D:getetag xmlns:D="DAV:">"abc"</D:getetag>`)
	if err := assert.PropExists(ms, "/alice/", "DAV:", "displayname"); err == nil {
		t.Error("expected error when property not in propstat")
	}
}

func TestPropExists_WrongNamespace(t *testing.T) {
	ms := buildMS("/alice/", `<D:displayname xmlns:D="DAV:">Alice</D:displayname>`)
	if err := assert.PropExists(ms, "/alice/", "urn:ietf:params:xml:ns:carddav", "displayname"); err == nil {
		t.Error("expected error for wrong namespace")
	}
}

func TestPropExists_EmptyMultistatus(t *testing.T) {
	ms := &client.Multistatus{}
	if err := assert.PropExists(ms, "/alice/", "DAV:", "displayname"); err == nil {
		t.Error("expected error for empty multistatus")
	}
}
