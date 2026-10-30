package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPromptShowsDecisionsAndStatus(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Errorf("status checked %s, want /readyz", r.URL.Path)
		}
	}))
	defer ready.Close()

	var out bytes.Buffer
	h := &history{out: &out}
	a := &app{verifier: verifier{baseURL: ready.URL, client: http.DefaultClient}, log: h.add}
	a.log("access denied: %s", "revoked")

	out.Reset()
	quit := repl(strings.NewReader("log\nstatus\nbogus\nquit\n"), &out, a, h)
	got := out.String()
	if !quit {
		t.Error("repl returned false on quit")
	}
	for _, want := range []string{"access denied: revoked", "HTTP 200", "unknown command"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}

func TestPromptVerifyDecidesLikeTheHTTPRoute(t *testing.T) {
	for _, tc := range []struct{ name, verifierReply, want string }{
		{"granted", `{"valid":true,"issuer":"did:example:issuer","claims":{"kyc_verified":true}}`, `"access":"granted"`},
		{"denied", `{"valid":false,"reason":"revoked"}`, `"reason":"revoked"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := fakeVerifier(t, 200, tc.verifierReply)
			var out bytes.Buffer
			h := &history{out: &bytes.Buffer{}}
			a := &app{verifier: verifier{baseURL: v.URL, client: http.DefaultClient}, log: h.add}

			repl(strings.NewReader("verify some-token\nverify\n"), &out, a, h)
			if !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "usage: verify") {
				t.Fatalf("output lacks %q or the usage hint:\n%s", tc.want, out.String())
			}
			if len(h.all()) != 1 {
				t.Fatalf("decisions logged = %d, want 1 (the empty verify must not call the verifier)", len(h.all()))
			}
		})
	}
}

func TestStatusReportsAnUnreachableVerifier(t *testing.T) {
	a := &app{verifier: verifier{baseURL: "http://127.0.0.1:1", client: http.DefaultClient}}
	if got := a.verifierStatus(); !strings.Contains(got, "unreachable") {
		t.Fatalf("status = %q, want unreachable", got)
	}
}

func TestPromptReturnsFalseAtEndOfInput(t *testing.T) {
	a := &app{verifier: verifier{baseURL: "http://127.0.0.1:1", client: http.DefaultClient}}
	if repl(strings.NewReader(""), &bytes.Buffer{}, a, &history{out: &bytes.Buffer{}}) {
		t.Fatal("repl returned true without a quit command: a service without a terminal would exit")
	}
}
