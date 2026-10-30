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
