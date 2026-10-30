package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cliUsage = `commands:
  status   check that the credential verifier is reachable and ready
  log      show the access decisions made so far
  help     show this list
  quit     stop the app`

// history records the app's access decisions and prints each one as it happens,
// so the operator sees a wallet's presentation land.
type history struct {
	out   io.Writer
	mu    sync.Mutex
	lines []string
}

func (h *history) add(format string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	h.mu.Lock()
	h.lines = append(h.lines, line)
	h.mu.Unlock()
	fmt.Fprintf(h.out, "\n%s\ndapp> ", line)
}

func (h *history) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

// repl reads commands until "quit" (returning true) or the end of input
// (returning false, so a service started without a terminal keeps running).
func repl(in io.Reader, out io.Writer, a *app, h *history) bool {
	fmt.Fprintln(out, "demo-dapp: type a command (help for the list)")
	sc := bufio.NewScanner(in)
	for fmt.Fprint(out, "dapp> "); sc.Scan(); fmt.Fprint(out, "dapp> ") {
		switch strings.TrimSpace(sc.Text()) {
		case "":
		case "help":
			fmt.Fprintln(out, cliUsage)
		case "status":
			fmt.Fprintln(out, a.verifierStatus())
		case "log":
			lines := h.all()
			if len(lines) == 0 {
				fmt.Fprintln(out, "no access decisions yet")
			}
			for _, l := range lines {
				fmt.Fprintln(out, l)
			}
		case "quit", "exit":
			return true
		default:
			fmt.Fprintln(out, "unknown command; type help")
		}
	}
	return false
}

// verifierStatus asks the verifier's readiness endpoint whether it is up.
func (a *app) verifierStatus() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.verifier.baseURL+"/readyz", nil)
	if err != nil {
		return err.Error()
	}
	resp, err := a.verifier.client.Do(req)
	if err != nil {
		return fmt.Sprintf("verifier %s: unreachable", a.verifier.baseURL)
	}
	resp.Body.Close()
	return fmt.Sprintf("verifier %s: HTTP %d", a.verifier.baseURL, resp.StatusCode)
}
