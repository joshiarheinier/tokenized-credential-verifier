// Command demo-wallet is a minimal credential wallet for the demo: it obtains a
// credential from the issuer, keeps it in a local directory, and presents it to
// a relying application.
//
// It is deliberately a separate program from the credential verifier backend and
// talks to it only over HTTP. It is a demonstration, not a real wallet: there is
// no user consent step, no key binding and no challenge-response, so a stolen
// credential file can be presented by anyone.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const usage = `usage: demo-wallet [command [flags]]

With no command, starts an interactive prompt where the commands below can be
typed one after another (help, exit).

commands:
  request   get a KYC credential from the issuer and store it
  list      show stored credentials
  present   present a stored credential to a relying application
  revoke    ask the issuer to revoke a stored credential (demo only: in real
            life the issuer revokes, not the holder)

common flags:
  -dir      wallet directory (env WALLET_DIR, default ./.wallet)`

func main() {
	if len(os.Args) < 2 {
		repl(os.Stdin, os.Stdout)
		return
	}
	if err := run(os.Args[1], os.Args[2:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// repl reads one command per line, as it would be typed after "demo-wallet",
// until "exit" or the end of input. A failing command is reported and the
// prompt carries on.
func repl(in io.Reader, out io.Writer) {
	fmt.Fprintln(out, "demo-wallet: type a command (help for the list, exit to quit)")
	sc := bufio.NewScanner(in)
	for fmt.Fprint(out, "wallet> "); sc.Scan(); fmt.Fprint(out, "wallet> ") {
		f := strings.Fields(sc.Text())
		switch {
		case len(f) == 0:
		case f[0] == "exit" || f[0] == "quit":
			return
		case f[0] == "help":
			fmt.Fprintln(out, usage)
		default:
			if err := run(f[0], f[1:], out); err != nil {
				fmt.Fprintln(out, "error:", err)
			}
		}
	}
}

func run(cmd string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", envOr("WALLET_DIR", ".wallet"), "wallet directory")
	switch cmd {
	case "request":
		api := fs.String("api", envOr("ISSUER_URL", "http://localhost:8080"), "base URL of the issuer API")
		subject := fs.String("subject", "did:example:demo-user", "subject the credential is issued to")
		country := fs.String("country", "ID", "country claim (ISO 3166-1 alpha-2)")
		verified := fs.Bool("kyc-verified", true, "kyc_verified claim")
		over18 := fs.Bool("over-18", true, "over_18 claim")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return request(out, store{*dir}, *api, *subject, map[string]any{
			"kyc_verified": *verified, "over_18": *over18, "country": *country,
		})
	case "list":
		if err := fs.Parse(args); err != nil {
			return err
		}
		return list(out, store{*dir})
	case "present":
		to := fs.String("to", envOr("DAPP_URL", "http://localhost:9090"), "base URL of the relying application")
		id := fs.String("id", "", "credential id (default: the newest)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return present(out, store{*dir}, *to, *id)
	case "revoke":
		api := fs.String("api", envOr("ISSUER_URL", "http://localhost:8080"), "base URL of the issuer API")
		id := fs.String("id", "", "credential id (default: the newest)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return revoke(out, store{*dir}, *api, *id)
	default:
		return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
	}
}

var httpClient = &http.Client{Timeout: 60 * time.Second} // issuing waits for on-chain confirmation

// request obtains a credential for subject and stores it.
//
// Real issuance starts with the issuer verifying the person. This demo has no
// such step, so it asks the backend's development-only simulation endpoint to
// record an approval, then redeems that approval for a credential.
func request(out io.Writer, s store, api, subject string, claims map[string]any) error {
	var approved struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := postJSON(api+"/v1/approvals/simulate", map[string]any{
		"subject": subject, "credential_type": "KYCStatus", "outcome": "approved", "claims": claims,
	}, &approved); err != nil {
		return fmt.Errorf("record approval: %w", err)
	}
	var issued struct {
		Credential string `json:"credential"`
	}
	if err := postJSON(api+"/v1/credentials", map[string]string{"approval_id": approved.ApprovalID}, &issued); err != nil {
		return fmt.Errorf("issue credential: %w", err)
	}
	c, err := s.save(issued.Credential, time.Now())
	if err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	fmt.Fprintf(out, "stored %s (%s, expires %s) in %s\n", c.ID, c.CredentialType, c.ExpiresAt.Format(time.RFC3339), displayDir(s.dir))
	return nil
}

func list(out io.Writer, s store) error {
	all, err := s.list()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Fprintln(out, "the wallet is empty")
		return nil
	}
	for _, c := range all {
		fmt.Fprintf(out, "%s  %-12s expires %s\n", c.ID, c.CredentialType, c.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// present sends a stored credential to the relying application and prints its
// answer. It returns an error if access was not granted, so scripts can rely on
// the exit status.
func present(out io.Writer, s store, to, id string) error {
	c, err := s.find(id)
	if err != nil {
		return err
	}
	var reply struct {
		Access string         `json:"access"`
		Reason string         `json:"reason"`
		Claims map[string]any `json:"claims"`
	}
	status, err := postJSONStatus(to+"/access", map[string]string{"credential": c.Credential}, &reply)
	if err != nil {
		return fmt.Errorf("present to %s: %w", to, err)
	}
	if reply.Access != "granted" {
		fmt.Fprintf(out, "denied (HTTP %d): %s\n", status, reply.Reason)
		return errors.New("access not granted")
	}
	fmt.Fprintf(out, "granted (HTTP %d), the application learned: %v\n", status, reply.Claims)
	return nil
}

// revoke asks the issuer to revoke a stored credential. Revocation is the
// issuer's action, so a real wallet would not have this command; the demo does
// so you can see a revoked credential refused. The credential stays in the
// wallet: it is still a validly signed token, the chain is what says otherwise.
func revoke(out io.Writer, s store, api, id string) error {
	c, err := s.find(id)
	if err != nil {
		return err
	}
	var reply struct {
		Error string `json:"error"`
	}
	status, err := postJSONStatus(api+"/v1/credentials/revoke", map[string]string{"credential": c.Credential}, &reply)
	if err != nil {
		return fmt.Errorf("revoke at %s: %w", api, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("the issuer refused (HTTP %d): %s", status, reply.Error)
	}
	fmt.Fprintf(out, "revoked %s on chain\n", c.ID)
	return nil
}

// postJSON posts body and decodes a 2xx reply into dst.
func postJSON(url string, body, dst any) error {
	status, err := postJSONStatus(url, body, dst)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("HTTP %d", status)
	}
	return nil
}

// postJSONStatus posts body, decodes the JSON reply into dst when there is one,
// and returns the HTTP status.
func postJSONStatus(url string, body, dst any) (int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("HTTP %d with an unreadable body", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

func displayDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
