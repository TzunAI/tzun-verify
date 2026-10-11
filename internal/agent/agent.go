// SPDX-License-Identifier: BSD-3-Clause-Clear

// Package agent reads an agent descriptor tzun-agent/1 (Record §6.9): its
// grammar, its digest and the limits a writer applies when it registers
// one. A b1 bundle carries no descriptor and a bundle verifier resolves no
// agent reference (Verification §4.8); a verifier that holds a descriptor's
// bytes re-hashes them with Digest.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/TzunAI/tzun-verify/internal/canonical"
	"github.com/TzunAI/tzun-verify/internal/grammar"
	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// Version is the descriptor format.
const Version = "tzun-agent/1"

// Writer limits of Record §6.9.
const (
	MaxBytes       = 16384
	MaxElements    = 64
	MaxString      = 256
	MaxAttestation = 8192
)

func member(v *jsonv.Value, key string) *jsonv.Value {
	m, _ := v.Get(key)
	return m
}

func nonEmpty(v *jsonv.Value) bool {
	s, ok := v.Str()
	return ok && s != "" || v != nil && v.Kind == jsonv.String && v.Lone && v.S != ""
}

func optPrefixed(v *jsonv.Value) bool {
	if grammar.IsNull(v) {
		return true
	}
	s, ok := v.Str()
	return ok && grammar.PrefixedDigest(s)
}

func base64url43(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// unique reports whether an array of non-empty strings holds no element
// twice, each meeting elem.
func unique(v *jsonv.Value, elem func(*jsonv.Value) bool) bool {
	if v == nil || v.Kind != jsonv.Array {
		return false
	}
	seen := map[string]bool{}
	for _, e := range v.A {
		if e.Kind != jsonv.String || !elem(e) || seen[e.S] {
			return false
		}
		seen[e.S] = true
	}
	return true
}

// Valid applies the grammar of Record §6.9: exactly the twelve members at
// every depth, each within its rule, and no element twice in a set.
func Valid(d *jsonv.Value) bool {
	if !grammar.Exact(d, "v", "name", "operator", "identities", "keys", "models", "instructions", "tools",
		"runtime", "policy", "parent", "derivation") {
		return false
	}
	if v, ok := member(d, "v").Str(); !ok || v != Version || !nonEmpty(member(d, "name")) {
		return false
	}
	op := member(d, "operator")
	if !grammar.Exact(op, "organization", "owner") || !nonEmpty(member(op, "organization")) {
		return false
	}
	if o := member(op, "owner"); !grammar.IsNull(o) {
		s, ok := o.Str()
		if !ok || !grammar.BareDigest(s) {
			return false
		}
	}
	if !unique(member(d, "identities"), nonEmpty) {
		return false
	}
	keys := member(d, "keys")
	if keys == nil || keys.Kind != jsonv.Array {
		return false
	}
	kids := map[string]bool{}
	for _, k := range keys.A {
		if !grammar.Exact(k, "kid", "alg", "custody", "attestation") {
			return false
		}
		kid, ok := member(k, "kid").Str()
		if !ok || !base64url43(kid) || kids[kid] {
			return false
		}
		kids[kid] = true
		switch alg, _ := member(k, "alg").Str(); alg {
		case "EdDSA", "ES256", "PS256":
		default:
			return false
		}
		switch c, _ := member(k, "custody").Str(); c {
		case "hsm", "tee", "workload", "software":
		default:
			return false
		}
		if a := member(k, "attestation"); !grammar.IsNull(a) && !nonEmpty(a) {
			return false
		}
	}
	if !unique(member(d, "models"), func(e *jsonv.Value) bool { s, ok := e.Str(); return ok && grammar.PrefixedDigest(s) }) {
		return false
	}
	for _, k := range []string{"instructions", "tools", "policy", "parent"} {
		if !optPrefixed(member(d, k)) {
			return false
		}
	}
	if rt := member(d, "runtime"); !grammar.IsNull(rt) {
		if !grammar.Exact(rt, "format", "measurements") || !nonEmpty(member(rt, "format")) ||
			!unique(member(rt, "measurements"), nonEmpty) {
			return false
		}
	}
	switch dv := member(d, "derivation"); {
	case grammar.IsNull(dv):
	default:
		switch s, _ := dv.Str(); s {
		case "base", "revision", "fork", "clone":
		default:
			return false
		}
	}
	return true
}

// sortedCopy returns d with identities, models and runtime.measurements
// sorted by the UTF-8 bytes of their elements and keys by the bytes of
// their kid: the d' a digest is taken over.
func sortedCopy(v *jsonv.Value) *jsonv.Value {
	cp := *v
	cp.O = append([]jsonv.Member(nil), v.O...)
	sortStrings := func(a *jsonv.Value) *jsonv.Value {
		if a == nil || a.Kind != jsonv.Array {
			return a
		}
		out := *a
		out.A = append([]*jsonv.Value(nil), a.A...)
		sort.SliceStable(out.A, func(i, j int) bool { return out.A[i].S < out.A[j].S })
		return &out
	}
	for i, m := range cp.O {
		switch m.Key {
		case "identities", "models":
			cp.O[i].Value = sortStrings(m.Value)
		case "keys":
			if m.Value != nil && m.Value.Kind == jsonv.Array {
				out := *m.Value
				out.A = append([]*jsonv.Value(nil), m.Value.A...)
				kid := func(k *jsonv.Value) string { s, _ := member(k, "kid").Str(); return s }
				sort.SliceStable(out.A, func(i, j int) bool { return kid(out.A[i]) < kid(out.A[j]) })
				cp.O[i].Value = &out
			}
		case "runtime":
			if rt := m.Value; rt != nil && rt.Kind == jsonv.Object {
				r := *rt
				r.O = append([]jsonv.Member(nil), rt.O...)
				for j, rm := range r.O {
					if rm.Key == "measurements" {
						r.O[j].Value = sortStrings(rm.Value)
					}
				}
				cp.O[i].Value = &r
			}
		}
	}
	return &cp
}

// Canonical is C(d'), the bytes a store keeps and a digest is taken over.
func Canonical(d *jsonv.Value) ([]byte, error) { return canonical.Serialize(sortedCopy(d)) }

// Digest is "sha256:" and hex(SHA-256(C(d'))).
func Digest(d *jsonv.Value) (string, error) {
	b, err := Canonical(d)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}

// WriterAccepts applies a writer's limits on top of the grammar: canonical
// bytes of at most 16 KiB, at most 64 elements in each array, at most 256
// code units in each string (8,192 in an attestation), and no lone
// surrogate.
func WriterAccepts(d *jsonv.Value) bool {
	if !Valid(d) {
		return false
	}
	b, err := Canonical(d)
	if err != nil || len(b) > MaxBytes {
		return false
	}
	ok := true
	var walk func(v *jsonv.Value, key string)
	walk = func(v *jsonv.Value, key string) {
		switch v.Kind {
		case jsonv.String:
			limit := MaxString
			if key == "attestation" {
				limit = MaxAttestation
			}
			if v.Lone || grammar.UTF16Len(v.S) > limit {
				ok = false
			}
		case jsonv.Array:
			if len(v.A) > MaxElements {
				ok = false
			}
			for _, e := range v.A {
				walk(e, key)
			}
		case jsonv.Object:
			for _, m := range v.O {
				walk(m.Value, m.Key)
			}
		}
	}
	walk(d, "")
	return ok
}

// PolicyEngineNamesModel reports whether a descriptor names a model, which
// a policy engine's must not (Record §6.4).
func PolicyEngineNamesModel(d *jsonv.Value) bool {
	m := member(d, "models")
	return m != nil && m.Kind == jsonv.Array && len(m.A) > 0
}
