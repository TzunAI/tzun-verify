package publishers

import (
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

func TestPinnedParses(t *testing.T) {
	v, err := jsonv.Parse(Pinned)
	if err != nil || v.Kind != jsonv.Object {
		t.Fatalf("the pinned manifest is not a JSON object: %v", err)
	}
	if len(SHA256()) != 64 {
		t.Fatal("SHA256 is not 64 hex characters")
	}
}
