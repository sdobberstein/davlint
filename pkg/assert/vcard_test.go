package assert_test

import (
	"testing"

	"github.com/sdobberstein/davlint/pkg/assert"
)

const sampleVCard = "BEGIN:VCARD\r\n" +
	"VERSION:4.0\r\n" +
	"FN:Alice Test\r\n" +
	"EMAIL;TYPE=work:alice@example.com\r\n" +
	"END:VCARD\r\n"

func TestHasProperty_Pass(t *testing.T) {
	if err := assert.HasProperty([]byte(sampleVCard), "FN"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHasProperty_CaseInsensitive(t *testing.T) {
	if err := assert.HasProperty([]byte(sampleVCard), "fn"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHasProperty_WithParams(t *testing.T) {
	// EMAIL;TYPE=work — the semicolon suffix should be recognised.
	if err := assert.HasProperty([]byte(sampleVCard), "EMAIL"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHasProperty_Missing(t *testing.T) {
	if err := assert.HasProperty([]byte(sampleVCard), "PHOTO"); err == nil {
		t.Error("expected error for missing property")
	}
}

func TestPropertyValue_Pass(t *testing.T) {
	if err := assert.PropertyValue([]byte(sampleVCard), "FN", "Alice Test"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPropertyValue_WrongValue(t *testing.T) {
	if err := assert.PropertyValue([]byte(sampleVCard), "FN", "Bob Test"); err == nil {
		t.Error("expected error for wrong value")
	}
}

func TestPropertyValue_Missing(t *testing.T) {
	if err := assert.PropertyValue([]byte(sampleVCard), "PHOTO", "anything"); err == nil {
		t.Error("expected error for missing property")
	}
}
