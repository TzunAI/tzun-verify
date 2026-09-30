//go:build js && wasm

// Command tzun-verify-wasm is tzun-verify built for the browser page in
// web/:
//
//	GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -tags purego \
//	  -o tzun-verify.wasm ./cmd/tzun-verify-wasm
//
// It runs the command itself (internal/cli.RunBytes) on bytes the page
// hands it: the flags an auditor would type, and the bytes of every file they
// name, the bundle included. Nothing is read from or written to anywhere
// else. A header source given with --evm-rpc is asked through the browser's
// fetch, since that is what Go's HTTP client uses in a browser; the page
// states the endpoint before any request is made. A redirect is refused,
// not followed, so that the endpoint the page states is the only host
// asked; the command follows redirects.
//
// It defines one global, tzunVerify:
//
//	tzunVerify.version               this build's version
//	tzunVerify.pinnedManifest        the pinned publisher manifest, as bytes (Uint8Array)
//	tzunVerify.pinnedManifestSHA256  its SHA-256, the digest a report names it by
//	tzunVerify.run(args, files)      a Promise of {exit, stdout, text, stderr}
//
// run's args is an array of strings and files an object from each name the
// args use to a Uint8Array. The result's stdout, text and stderr are
// Uint8Arrays: what the command prints on standard output (the JSON report
// with --json), the text report of the same verification, and what it prints
// on standard error.
package main

import (
	"fmt"
	"net/http"
	"syscall/js"

	"github.com/TzunAI/tzun-verify/internal/cli"
	"github.com/TzunAI/tzun-verify/publishers"
)

func toJS(b []byte) js.Value {
	a := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(a, b)
	return a
}

func fromJS(v js.Value) ([]byte, error) {
	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, fmt.Errorf("not a Uint8Array")
	}
	b := make([]byte, v.Length())
	js.CopyBytesToGo(b, v)
	return b, nil
}

// run is tzunVerify.run. It reads its arguments before it returns, and
// verifies in a goroutine: a call to a header source waits on fetch, which
// only a goroutine outside the JavaScript callback may do.
func run(_ js.Value, in []js.Value) any {
	promise := js.Global().Get("Promise")
	var args []string
	files := map[string][]byte{}
	err := func() error {
		if len(in) != 2 || !js.Global().Get("Array").Call("isArray", in[0]).Bool() || in[1].Type() != js.TypeObject {
			return fmt.Errorf("run(args, files): args an array of strings, files an object of Uint8Arrays")
		}
		for i := 0; i < in[0].Length(); i++ {
			a := in[0].Index(i)
			if a.Type() != js.TypeString {
				return fmt.Errorf("args[%d] is not a string", i)
			}
			args = append(args, a.String())
		}
		names := js.Global().Get("Object").Call("keys", in[1])
		for i := 0; i < names.Length(); i++ {
			name := names.Index(i).String()
			b, err := fromJS(in[1].Get(name))
			if err != nil {
				return fmt.Errorf("files[%q]: %v", name, err)
			}
			files[name] = b
		}
		return nil
	}()
	if err != nil {
		return promise.Call("reject", js.Global().Get("Error").New(err.Error()))
	}
	executor := js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve, reject := p[0], p[1]
		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(js.Global().Get("Error").New(fmt.Sprint("tzun-verify: ", r)))
				}
			}()
			out := cli.RunBytes(args, files)
			res := js.Global().Get("Object").New()
			res.Set("exit", out.Exit)
			res.Set("stdout", toJS(out.Stdout))
			res.Set("text", toJS(out.Text))
			res.Set("stderr", toJS(out.Stderr))
			resolve.Invoke(res)
		}()
		return nil
	})
	defer executor.Release()
	return promise.New(executor)
}

// noRedirects is the HTTP transport of this build. It asks the browser's
// fetch to fail on a redirect (Go's js/wasm transport reads the
// "js.fetch:redirect" header as fetch's redirect option and does not send
// it), so that a request goes to the endpoint named and to no other host.
type noRedirects struct{ next http.RoundTripper }

func (t noRedirects) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("js.fetch:redirect", "error")
	return t.next.RoundTrip(r)
}

func main() {
	http.DefaultTransport = noRedirects{http.DefaultTransport}
	api := js.Global().Get("Object").New()
	api.Set("version", cli.Version)
	api.Set("pinnedManifest", toJS(publishers.Pinned))
	api.Set("pinnedManifestSHA256", publishers.SHA256())
	api.Set("run", js.FuncOf(run))
	js.Global().Set("tzunVerify", api)
	select {}
}
