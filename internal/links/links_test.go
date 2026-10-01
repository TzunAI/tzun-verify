package links

import (
	"strings"
	"testing"
)

// TestLocatorOrigin: the origin grammar of a locator (Record §8.2): a
// store's evidence log, or a hosted log under exactly log.tzun.ai or
// test.log.tzun.ai, never an anchor log.
func TestLocatorOrigin(t *testing.T) {
	store := strings.Repeat("0f", 16)
	for _, c := range []struct {
		origin string
		ok     bool
	}{
		{"test.lender.example/" + store + "/evidence/6c656e64696e67", true},
		{"lender.example/" + store + "/evidence/6c656e64696e67", true},
		{"Lender.example/" + store + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + strings.ToUpper(store) + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + store[:30] + "/evidence/6c656e64696e67", false},
		{"test.lender.example/" + store + "/evidence/6C656e64696e67", false},
		{"test.lender.example/" + store + "/custody", false},
		{"test.lender.example/" + store + "/anchors", false},
		{"log.tzun.ai/" + store + "/" + store, true},
		{"test.log.tzun.ai/" + store + "/" + store, true},
		{"log.tzun.ai/" + store + "/anchors", false},
		{"staging.log.tzun.ai/" + store + "/" + store, false},
	} {
		if validOrigin(c.origin) != c.ok {
			t.Errorf("%s: %v", c.origin, !c.ok)
		}
	}
}

// TestRelationNames: the grammar of a registered name and of an extension
// name (Record §8.2), and the registry of §8.3.
func TestRelationNames(t *testing.T) {
	for _, c := range []struct {
		name                   string
		valid, ext, registered bool
	}{
		{"derivedFrom", true, false, true},
		{"subject", true, false, true},
		{"inspiredBy", true, false, false},
		{"x-acme.contractRenewal", true, true, false},
		{"x-a.b", true, true, false},
		{"x-acme-.renewal", false, false, false},
		{"x-" + strings.Repeat("o", 32) + "." + strings.Repeat("n", 32), true, true, false},
		{"x-" + strings.Repeat("o", 32) + "." + strings.Repeat("n", 33), false, false, false},
		{"a" + strings.Repeat("b", 31), true, false, false},
		{"a" + strings.Repeat("b", 32), false, false, false},
	} {
		if validName(c.name) != c.valid || Extension(c.name) != c.ext || Registered(c.name) != c.registered {
			t.Errorf("%s: valid %v extension %v registered %v", c.name, validName(c.name), Extension(c.name), Registered(c.name))
		}
	}
}
