// SPDX-License-Identifier: BSD-3-Clause-Clear

package publishers

import (
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
	"github.com/TzunAI/tzun-verify/internal/manifest"
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

// Every origin the pinned manifest lists reads as entries a verifier uses
// (Anchor §9): none is unreadable, which would leave every publication from
// that origin unchecked.
func TestPinnedEntriesRead(t *testing.T) {
	v, err := jsonv.Parse(Pinned)
	if err != nil {
		t.Fatal(err)
	}
	pubs, ok := v.Get("publishers")
	if !ok || pubs.Kind != jsonv.Object {
		t.Fatal("the pinned manifest has no publishers object")
	}
	if len(pubs.Keys()) == 0 {
		t.Fatal("the pinned manifest lists no origin")
	}
	for _, origin := range pubs.Keys() {
		if got := manifest.ForOrigin(v, origin); got.State != manifest.OK {
			t.Errorf("%s: state %v, entries %v", origin, got.State, got.Entries)
		}
	}
}
