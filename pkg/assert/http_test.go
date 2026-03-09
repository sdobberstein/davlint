package assert_test

import (
	"net/http"
	"testing"

	"github.com/sdobberstein/davlint/pkg/assert"
	"github.com/sdobberstein/davlint/pkg/client"
)

func resp(code int, headers map[string]string) *client.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &client.Response{StatusCode: code, Header: h}
}

func TestStatusCode_Pass(t *testing.T) {
	if err := assert.StatusCode(resp(207, nil), 207); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStatusCode_Fail(t *testing.T) {
	if err := assert.StatusCode(resp(404, nil), 207); err == nil {
		t.Error("expected error for wrong status code")
	}
}

func TestHeader_Pass(t *testing.T) {
	r := resp(200, map[string]string{"DAV": "1, 2, addressbook"})
	if err := assert.Header(r, "DAV", "1, 2, addressbook"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHeader_CaseInsensitiveValue(t *testing.T) {
	r := resp(200, map[string]string{"Content-Type": "text/vcard; charset=utf-8"})
	if err := assert.Header(r, "Content-Type", "TEXT/VCARD; CHARSET=UTF-8"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHeader_Fail(t *testing.T) {
	r := resp(200, map[string]string{"DAV": "1"})
	if err := assert.Header(r, "DAV", "1, 2, addressbook"); err == nil {
		t.Error("expected error for wrong header value")
	}
}

func TestHeader_Missing(t *testing.T) {
	if err := assert.Header(resp(200, nil), "DAV", "1"); err == nil {
		t.Error("expected error for missing header")
	}
}

func TestHeaderContains_Pass(t *testing.T) {
	r := resp(200, map[string]string{"DAV": "1, 2, access-control, addressbook"})
	if err := assert.HeaderContains(r, "DAV", "addressbook"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHeaderContains_Fail(t *testing.T) {
	r := resp(200, map[string]string{"DAV": "1, 2"})
	if err := assert.HeaderContains(r, "DAV", "addressbook"); err == nil {
		t.Error("expected error when substring not present")
	}
}
