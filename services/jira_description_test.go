package services

import (
	"strings"
	"testing"
)

func TestFormatDescriptionExtractsADFText(t *testing.T) {
	desc := map[string]interface{}{
		"type": "doc",
		"content": []interface{}{
			map[string]interface{}{
				"type": "paragraph",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "Ship "},
					map[string]interface{}{"type": "text", "text": "backend"},
				},
			},
		},
	}

	if got := formatDescription(desc); got != "Ship backend" {
		t.Fatalf("expected extracted ADF text, got %q", got)
	}
}

func TestFormatDescriptionFallsBackToJSON(t *testing.T) {
	desc := map[string]interface{}{"unknown": "value"}

	if got := formatDescription(desc); got != `{"unknown":"value"}` {
		t.Fatalf("expected JSON fallback, got %q", got)
	}
}

func TestFormatDescriptionTruncatesLongText(t *testing.T) {
	desc := map[string]interface{}{
		"type": "paragraph",
		"content": []interface{}{
			map[string]interface{}{"type": "text", "text": strings.Repeat("a", 501)},
		},
	}

	got := formatDescription(desc)
	if len(got) != 503 || !strings.HasSuffix(got, "...") {
		t.Fatalf("expected 500 character truncation with suffix, got length %d", len(got))
	}
}
