// SPDX-License-Identifier: BSD-3-Clause-Clear

package checkpoint

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TzunAI/tzun-verify/internal/jsonv"
)

// checkpointVectors reads the bodies, chain segments and domain cases of
// checkpoint-vectors.json, for seeds.
func checkpointVectors(f *testing.F) (doc struct {
	Bodies struct {
		Valid, Invalid []struct {
			Body string `json:"body"`
		}
	} `json:"bodies"`
	ChainSegments struct {
		Valid []struct {
			ChainID string `json:"chainId"`
			Segment string `json:"segment"`
		} `json:"valid"`
		Invalid []struct {
			Segment string `json:"segment"`
		} `json:"invalid"`
		Unencodable []struct {
			ChainID string `json:"chainId"`
		} `json:"unencodable"`
	} `json:"chainSegments"`
	Domain []struct {
		AnchorOrigin string  `json:"anchorOrigin"`
		LogOrigin    string  `json:"logOrigin"`
		ChainID      *string `json:"chainId"`
	} `json:"domain"`
}) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "checkpoint-vectors.json"))
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		f.Fatal(err)
	}
	return doc
}

// FuzzParseString holds ParseString to §4.2 on any string: a body it
// accepts is exactly the three lines origin, size and root, the size in
// [1, MaxSize] written without a leading zero and the root 32 bytes in
// canonical base64, so writing the parts back gives the input byte for byte;
// Parse agrees on the same text as a JSON string, and the digest is SHA-256
// of the body's bytes.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzParseString fuzzes.
func FuzzParseString(f *testing.F) {
	doc := checkpointVectors(f)
	for _, c := range doc.Bodies.Valid {
		f.Add(c.Body)
	}
	for _, c := range doc.Bodies.Invalid {
		f.Add(c.Body)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, ok := ParseString(s)
		pb, pok := Parse(&jsonv.Value{Kind: jsonv.String, S: s})
		if ok != pok || (ok && (pb.Raw != b.Raw || pb.Size != b.Size)) {
			t.Fatalf("Parse and ParseString disagree on %q", s)
		}
		if !ok {
			if b != nil {
				t.Fatalf("a body returned with a refusal")
			}
			return
		}
		if b.Raw != s || b.Size < 1 || b.Size > MaxSize || len(b.Root) != 32 || b.Origin == "" {
			t.Fatalf("%q: origin %q size %d root %x", s, b.Origin, b.Size, b.Root)
		}
		if again := b.Origin + "\n" + strconv.FormatUint(b.Size, 10) + "\n" + base64.StdEncoding.EncodeToString(b.Root) + "\n"; again != s {
			t.Fatalf("%q is not the body its parts write: %q", s, again)
		}
		sum := sha256.Sum256([]byte(s))
		if DigestHex(s) != hex.EncodeToString(sum[:]) {
			t.Fatalf("checkpointDigest is not SHA-256 of the body")
		}
	})
}

// FuzzChainSegment holds the chain segment rule of §4.3.2 to a round trip
// in both directions: a segment the reader decodes is the one the writer
// encodes for that chain id, and a chain id the writer encodes decodes to
// itself.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzChainSegment fuzzes.
func FuzzChainSegment(f *testing.F) {
	doc := checkpointVectors(f)
	for _, c := range doc.ChainSegments.Valid {
		f.Add(c.Segment)
		f.Add(c.ChainID)
	}
	for _, c := range doc.ChainSegments.Invalid {
		f.Add(c.Segment)
	}
	for _, c := range doc.ChainSegments.Unencodable {
		f.Add(c.ChainID)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if chain, ok := DecodeChainSegment(s); ok {
			if seg, ok := EncodeChainSegment(chain); !ok || seg != s {
				t.Fatalf("segment %q decodes to %q, which encodes to %q (%v)", s, chain, seg, ok)
			}
		}
		if seg, ok := EncodeChainSegment(s); ok {
			if chain, ok := DecodeChainSegment(seg); !ok || chain != s {
				t.Fatalf("chain id %q encodes to %q, which decodes to %q (%v)", s, seg, chain, ok)
			}
		}
	})
}

// FuzzBind holds ParseOrigin, Bind and BindRecord to §4.3 on any pair of
// origins and chain id. An origin ParseOrigin reads is the segments it
// names, joined again; an evidence origin's chain segment is the one its
// chain id encodes to. Bind gives one of its three results; ok only for an
// anchors origin and a non-anchors origin of one domain prefix, and a
// checked chain only for an evidence log of that very chain. BindRecord is
// ok only where Bind is.
//
// go test runs the seeds; go test -run='^$' -fuzz=FuzzBind fuzzes.
func FuzzBind(f *testing.F) {
	doc := checkpointVectors(f)
	for _, c := range doc.Domain {
		chain, has := "", c.ChainID != nil
		if has {
			chain = *c.ChainID
		}
		f.Add(c.AnchorOrigin, c.LogOrigin, chain, has, true)
	}
	f.Fuzz(func(t *testing.T, anchorOrigin, logOrigin, chain string, has, chainOK bool) {
		for _, s := range []string{anchorOrigin, logOrigin} {
			o, ok := ParseOrigin(s)
			if !ok {
				continue
			}
			segs := strings.Split(s, "/")
			if o.Raw != s || o.Namespace != segs[0] || o.Prefix != segs[0]+"/"+segs[1] {
				t.Fatalf("%q: raw %q prefix %q namespace %q", s, o.Raw, o.Prefix, o.Namespace)
			}
			var rest string
			switch o.Kind {
			case KindAnchors:
				rest = "anchors"
			case KindOther:
				rest = o.Segment
			case KindEvidence:
				rest = "evidence/" + o.Segment
				if seg, ok := EncodeChainSegment(o.ChainID); !ok || seg != o.Segment {
					t.Fatalf("%q: chain %q encodes to %q", s, o.ChainID, seg)
				}
			default:
				t.Fatalf("%q: kind %d", s, o.Kind)
			}
			if o.Prefix+"/"+rest != s {
				t.Fatalf("%q is not its parts joined: %q", s, o.Prefix+"/"+rest)
			}
		}
		var id *string
		if has {
			id = &chain
		}
		r := Bind(anchorOrigin, logOrigin, id, chainOK)
		switch r.Result {
		case BindOK:
			ao, ok1 := ParseOrigin(anchorOrigin)
			lo, ok2 := ParseOrigin(logOrigin)
			if !ok1 || !ok2 || ao.Kind != KindAnchors || lo.Kind == KindAnchors || ao.Prefix != lo.Prefix || r.Namespace != lo.Namespace {
				t.Fatalf("Bind(%q, %q) is ok", anchorOrigin, logOrigin)
			}
			if r.ChainChecked && (id == nil || !chainOK || lo.Kind != KindEvidence || lo.ChainID != chain) {
				t.Fatalf("Bind(%q, %q, %q) checked the chain", anchorOrigin, logOrigin, chain)
			}
			if id != nil && !r.ChainChecked && !IsPlatformNamespace(lo.Namespace) {
				t.Fatalf("Bind(%q, %q, %q) left the chain unchecked outside the platform namespaces", anchorOrigin, logOrigin, chain)
			}
		case BindNotInDomain, BindChainIDMismatch:
		default:
			t.Fatalf("Bind result %q", r.Result)
		}
		if rr := BindRecord(anchorOrigin, logOrigin, id, chainOK); rr.Result == BindOK && r.Result != BindOK {
			t.Fatalf("BindRecord(%q, %q) is ok where Bind is %s", anchorOrigin, logOrigin, r.Result)
		}
	})
}
