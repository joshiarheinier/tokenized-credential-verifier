package main

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The web side of the demo application: a members-only area for people over 18.
// Instead of asking for a credential, it asks the user's wallet to prove one
// claim, over_18, and learns nothing else.
//
//	/            what this is, and the "Verify with wallet" button
//	/start       (POST) poses a challenge and sends the browser to the wallet
//	/callback    where the wallet sends the browser back; reads the verdict
//	/members     the members-only area, for browsers whose wallet proved over_18

const (
	sessionCookie  = "dapp_session"
	sessionTTL     = 30 * time.Minute
	maxSessions    = 1000
	requestedType  = "KYCStatus"
	requestedClaim = "over_18"
)

type site struct {
	app *app
	// audience is this application's own origin, as the user's browser sees it.
	audience string
	// wallet is the origin of the user's wallet web app.
	wallet   string
	sessions *sessions
}

func (s *site) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("POST /start", s.start)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("GET /members", s.members)
	mux.HandleFunc("POST /signout", s.signOut)
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(styleCSS))
	})
	// The bare credential check from before the wallet existed, kept for curl.
	mux.HandleFunc("POST /access", s.app.access)
	return s.secure(mux)
}

// secure sends 127.0.0.1 to the configured address (the session cookie, the
// wallet and Phantom all go by "localhost") and adds the security headers.
func (s *site) secure(next http.Handler) http.Handler {
	policy := "default-src 'none'; style-src 'self'; form-action 'self' " + origin(s.wallet) + "; base-uri 'none'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err == nil && host == "127.0.0.1" {
			http.Redirect(w, r, s.audience+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "'none'"
	}
	return u.Scheme + "://" + u.Host
}

// --- pages -------------------------------------------------------------------

type learned struct {
	Name  string
	Value any
}

type view struct {
	Title       string
	Notice      string
	IsError     bool
	Body        string
	Learned     []learned
	CheckAgain  string // challenge id to check again, if any
	ShowStart   bool
	ShowSignOut bool
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <main>
    <h1>{{.Title}}</h1>
    {{if .Notice}}<p class="notice{{if .IsError}} error{{end}}">{{.Notice}}</p>{{end}}
    {{if .Body}}<p>{{.Body}}</p>{{end}}
    {{if .Learned}}
    <h2>What this application learned</h2>
    <dl>{{range .Learned}}<dt>{{.Name}}</dt><dd>{{.Value}}</dd>{{end}}</dl>
    <p class="hint">Nothing else: not your country, not who you are.</p>
    {{end}}
    {{if .CheckAgain}}<p><a href="/callback?challenge={{.CheckAgain}}">Check again</a></p>{{end}}
    {{if .ShowStart}}<form method="post" action="/start"><button class="primary">Verify with wallet</button></form>{{end}}
    {{if .ShowSignOut}}<form method="post" action="/signout"><button>Sign out</button></form>{{end}}
  </main>
</body>
</html>
`))

func (s *site) render(w http.ResponseWriter, status int, v view) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, v)
}

// session returns the browser's session, if it has a live one.
func (s *site) session(r *http.Request) (string, session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", session{}, false
	}
	sess, ok := s.sessions.get(c.Value)
	return c.Value, sess, ok
}

func (s *site) home(w http.ResponseWriter, r *http.Request) {
	if _, sess, ok := s.session(r); ok && sess.Verified {
		http.Redirect(w, r, "/members", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, view{
		Title: "Members area",
		Body: "This area is for people over 18. To get in, prove it with your wallet. " +
			"This application will learn only whether you are over 18.",
		ShowStart: true,
	})
}

func (s *site) start(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), verifierTimeout)
	defer cancel()
	c, err := s.app.verifier.createChallenge(ctx, s.audience, requestedType, []string{requestedClaim}, s.audience+"/callback")
	if err != nil {
		s.app.log("could not start verification: %v", err)
		s.render(w, http.StatusServiceUnavailable, view{
			Title: "Cannot verify right now", IsError: true,
			Notice: "The verifier could not be reached, so nobody can be let in. Try again in a moment.", ShowStart: true,
		})
		return
	}
	id, err := s.sessions.create(c)
	if err != nil {
		s.render(w, http.StatusServiceUnavailable, view{Title: "Busy", IsError: true, Notice: "Too many people are signing in. Try again shortly."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(s.audience, "https://"), MaxAge: int(sessionTTL.Seconds()),
	})
	s.app.log("asked a wallet to prove %s", requestedClaim)
	http.Redirect(w, r, s.wallet+"/present?challenge="+url.QueryEscape(c.ID), http.StatusSeeOther)
}

func (s *site) callback(w http.ResponseWriter, r *http.Request) {
	id, sess, ok := s.session(r)
	// Only the browser that started the verification may read its result: a
	// challenge id in a URL is not a secret.
	if !ok || sess.Challenge.ID != r.URL.Query().Get("challenge") {
		s.render(w, http.StatusBadRequest, view{
			Title: "Start from the home page", IsError: true,
			Notice:    "This page only works in the browser that started the verification.",
			ShowStart: true,
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), verifierTimeout)
	defer cancel()
	res, err := s.app.verifier.result(ctx, sess.Challenge)
	if err != nil {
		s.app.log("could not read the verdict: %v", err)
		s.render(w, http.StatusServiceUnavailable, view{
			Title: "Cannot verify right now", IsError: true,
			Notice: "The verifier could not be reached, so nobody can be let in.", CheckAgain: sess.Challenge.ID,
		})
		return
	}

	switch res.Status {
	case "verified":
		s.sessions.markVerified(id, res.Claims)
		s.app.log("wallet answered: %s = %v", requestedClaim, res.Claims[requestedClaim])
		http.Redirect(w, r, "/members", http.StatusSeeOther)
	case "pending":
		s.render(w, http.StatusOK, view{
			Title:      "Still waiting for your wallet",
			Notice:     "Your wallet has not answered yet. If you declined, you can start again.",
			CheckAgain: sess.Challenge.ID, ShowStart: true,
		})
	case "rejected":
		s.app.log("wallet answer refused: %s", res.Reason)
		s.render(w, http.StatusForbidden, view{
			Title: "Not verified", IsError: true, Notice: reasonText(res.Reason), ShowStart: true,
		})
	case "expired":
		s.render(w, http.StatusGone, view{
			Title: "That took too long", IsError: true, Notice: "The request expired before your wallet answered.", ShowStart: true,
		})
	default: // unavailable, or anything we do not understand: never let anyone in
		s.app.log("verifier could not decide (%s)", res.Status)
		s.render(w, http.StatusServiceUnavailable, view{
			Title: "Cannot verify right now", IsError: true,
			Notice: "The verifier could not check your credential, so nobody can be let in. Start again in a moment.", ShowStart: true,
		})
	}
}

func (s *site) members(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.session(r)
	if !ok || !sess.Verified {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// The application decides from the claim it asked for.
	value := sess.Claims[requestedClaim]
	claims := []learned{{Name: requestedClaim, Value: value}}
	if value != true {
		s.render(w, http.StatusForbidden, view{
			Title: "Not eligible", IsError: true,
			Notice:  "Your wallet proved a credential, but it says you are not over 18.",
			Learned: claims, ShowStart: true, ShowSignOut: true,
		})
		return
	}
	s.render(w, http.StatusOK, view{
		Title: "Welcome to the members area", Body: "You proved you are over 18.", Learned: claims, ShowSignOut: true,
	})
}

func (s *site) signOut(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// reasonText is the verifier's reason in plain language.
func reasonText(reason string) string {
	switch reason {
	case "revoked":
		return "The credential has been revoked by its issuer."
	case "expired":
		return "The credential has expired."
	case "untrusted_issuer":
		return "The credential's issuer is not trusted."
	case "holder_binding_failed":
		return "The credential is not bound to the account that signed."
	case "claim_unavailable":
		return "The credential does not provide what was asked for."
	case "policy_not_satisfied":
		return "The credential does not meet this application's requirements."
	case "not_registered":
		return "The credential is not registered with the trust registry."
	default:
		return "The verifier refused the credential."
	}
}

const styleCSS = `
:root { --bg:#f6f7f9; --card:#fff; --text:#1c2330; --muted:#5d6778; --line:#d9dee7; --accent:#4b3fd6; --accent-text:#fff; --ok:#17703b; --ok-bg:#e5f5ec; --bad:#a3262a; --bad-bg:#fbe9ea; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171d; --card:#1d222b; --text:#e8ebf1; --muted:#9aa4b5; --line:#333b49; --accent:#8f86ff; --accent-text:#14171d; --ok:#6fd49a; --ok-bg:#173325; --bad:#ff8f93; --bad-bg:#3a1c1e; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:36rem; margin:0 auto; padding:2rem 16px; }
h1 { font-size:1.5rem; margin:0 0 1rem; }
h2 { font-size:1.05rem; margin:1.5rem 0 .5rem; }
button { font:inherit; padding:.5rem 1rem; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--text); cursor:pointer; }
button.primary { background:var(--accent); color:var(--accent-text); border-color:var(--accent); }
.notice { padding:.6rem .8rem; border-radius:8px; background:var(--ok-bg); color:var(--ok); }
.notice.error { background:var(--bad-bg); color:var(--bad); }
.hint { color:var(--muted); font-size:.92rem; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:.2rem 1rem; margin:0; }
dt { color:var(--muted); } dd { margin:0; }
form { display:inline; margin-right:.5rem; }
a { color:var(--accent); }
`
