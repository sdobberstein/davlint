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

// --- PropHrefContains ---

func TestPropHrefContains_Pass_DAVNamespace(t *testing.T) {
	ms := buildMS("/dav/", `<D:current-user-principal xmlns:D="DAV:"><D:href>/dav/principals/users/alice/</D:href></D:current-user-principal>`)
	if err := assert.PropHrefContains(ms, "/dav/", "DAV:", "current-user-principal", "/dav/principals/users/alice/"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropHrefContains_Pass_CardDAVNamespace(t *testing.T) {
	ms := buildMS("/dav/principals/users/alice/",
		`<C:addressbook-home-set xmlns:C="urn:ietf:params:xml:ns:carddav" xmlns:D="DAV:"><D:href>/dav/addressbooks/alice/</D:href></C:addressbook-home-set>`)
	if err := assert.PropHrefContains(ms, "/dav/principals/users/alice/",
		"urn:ietf:params:xml:ns:carddav", "addressbook-home-set", "/dav/addressbooks/alice/"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropHrefContains_Pass_SubstringMatch(t *testing.T) {
	// href in response may be a full URL; substring match still passes
	ms := buildMS("/dav/", `<D:current-user-principal xmlns:D="DAV:"><D:href>http://localhost:8080/dav/principals/users/alice/</D:href></D:current-user-principal>`)
	if err := assert.PropHrefContains(ms, "/dav/", "DAV:", "current-user-principal", "/dav/principals/users/alice/"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropHrefContains_Fail_SubstringMissing(t *testing.T) {
	ms := buildMS("/dav/", `<D:current-user-principal xmlns:D="DAV:"><D:href>/dav/principals/users/bob/</D:href></D:current-user-principal>`)
	if err := assert.PropHrefContains(ms, "/dav/", "DAV:", "current-user-principal", "/dav/principals/users/alice/"); err == nil {
		t.Error("expected error when href does not contain expected substring")
	}
}

func TestPropHrefContains_Fail_PropNotPresent(t *testing.T) {
	ms := buildMS("/dav/", `<D:displayname xmlns:D="DAV:">Alice</D:displayname>`)
	if err := assert.PropHrefContains(ms, "/dav/", "DAV:", "current-user-principal", "/dav/principals/"); err == nil {
		t.Error("expected error when property is absent")
	}
}

func TestPropHrefContains_Fail_NoHrefChild(t *testing.T) {
	ms := buildMS("/dav/", `<D:current-user-principal xmlns:D="DAV:"><D:unauthenticated/></D:current-user-principal>`)
	if err := assert.PropHrefContains(ms, "/dav/", "DAV:", "current-user-principal", "/dav/"); err == nil {
		t.Error("expected error when property has no DAV:href child")
	}
}

func TestPropHrefContains_Fail_HrefNotFound(t *testing.T) {
	ms := buildMS("/dav/", `<D:current-user-principal xmlns:D="DAV:"><D:href>/dav/principals/users/alice/</D:href></D:current-user-principal>`)
	if err := assert.PropHrefContains(ms, "/wrong/", "DAV:", "current-user-principal", "/dav/"); err == nil {
		t.Error("expected error when href not in multistatus")
	}
}

// --- PropHrefValue ---

func TestPropHrefValue_Pass(t *testing.T) {
	ms := buildMS("/ctx/", `<D:current-user-principal xmlns:D="DAV:"><D:href>/principals/alice/</D:href></D:current-user-principal>`)
	got, err := assert.PropHrefValue(ms, "/ctx/", "DAV:", "current-user-principal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/principals/alice/" {
		t.Errorf("got %q, want %q", got, "/principals/alice/")
	}
}

func TestPropHrefValue_Fail_HrefNotFound(t *testing.T) {
	ms := buildMS("/ctx/", `<D:current-user-principal xmlns:D="DAV:"><D:href>/principals/alice/</D:href></D:current-user-principal>`)
	if _, err := assert.PropHrefValue(ms, "/wrong/", "DAV:", "current-user-principal"); err == nil {
		t.Error("expected error when href not in multistatus")
	}
}

func TestPropHrefValue_Fail_PropAbsent(t *testing.T) {
	ms := buildMS("/ctx/", `<D:displayname xmlns:D="DAV:">Alice</D:displayname>`)
	if _, err := assert.PropHrefValue(ms, "/ctx/", "DAV:", "current-user-principal"); err == nil {
		t.Error("expected error when property is absent")
	}
}
