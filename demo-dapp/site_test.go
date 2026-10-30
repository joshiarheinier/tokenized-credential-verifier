package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVerifier is the verifier's challenge API with a scripted verdict.
type fakeChallengeAPI struct {
	mu           sync.Mutex
	created      []map[string]any
	resultStatus int
	result       string
	down         bool
}

func (f *fakeChallengeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/challenges":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.created = append(f.created, body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"challenge_id":"chal-1","result_secret":"secret-1"}`))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/challenges/chal-1/result":
		if r.Header.Get("Authorization") != "Bearer secret-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(f.resultStatus)
		_, _ = w.Write([]byte(f.result))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type siteEnv struct {
	t        *testing.T
	api      *fakeChallengeAPI
	srv      *httptest.Server
	client   *http.Client
	hostPort string
}

func newSiteEnv(t *testing.T) *siteEnv {
	t.Helper()
	api := &fakeChallengeAPI{resultStatus: 200, result: `{"status":"pending"}`}
	verifierSrv := httptest.NewServer(api)
	t.Cleanup(verifierSrv.Close)

	s := &site{
		app:      &app{verifier: verifier{baseURL: verifierSrv.URL, client: http.DefaultClient}, log: t.Logf},
		audience: "http://localhost:9090",
		wallet:   "http://localhost:9091",
		sessions: newSessions(10, time.Minute),
	}
	srv := httptest.NewServer(s.routes())
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	u, _ := neturl.Parse(srv.URL)
	return &siteEnv{
		t: t, api: api, srv: srv, hostPort: u.Port(),
		client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// do requests the site as a browser at http://localhost:<port> would.
func (e *siteEnv) do(method, path string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = "localhost:" + e.hostPort
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (e *siteEnv) startVerification() {
	e.t.Helper()
	resp, _ := e.do("POST", "/start")
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("POST /start = %d, want a redirect to the wallet", resp.StatusCode)
	}
}

func TestHomePageOffersToVerifyWithTheWallet(t *testing.T) {
	e := newSiteEnv(t)
	resp, body := e.do("GET", "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Verify with wallet") {
		t.Fatalf("GET / = %d %q", resp.StatusCode, body)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://localhost:9091") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("policy %q must allow the form to go on to the wallet and nothing else", csp)
	}
}

func TestStartingSendsTheBrowserToTheWalletAskingForOneClaim(t *testing.T) {
	e := newSiteEnv(t)
	resp, _ := e.do("POST", "/start")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "http://localhost:9091/present?challenge=chal-1" {
		t.Fatalf("got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if len(e.api.created) != 1 {
		t.Fatalf("challenges created = %d, want 1", len(e.api.created))
	}
	asked := e.api.created[0]
	claims, _ := asked["claims"].([]any)
	if asked["audience"] != "http://localhost:9090" || asked["credential_type"] != "KYCStatus" ||
		len(claims) != 1 || claims[0] != "over_18" || asked["callback_url"] != "http://localhost:9090/callback" {
		t.Fatalf("challenge asked for = %v, want only over_18, for this app, calling back to /callback", asked)
	}

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v, want HttpOnly and SameSite=Lax", cookie)
	}
	if strings.Contains(resp.Header.Get("Location"), "secret-1") || strings.Contains(cookie.Value, "secret-1") {
		t.Fatal("the result secret leaked into the browser")
	}
}

func TestVerifiedOverEighteenIsLetIn(t *testing.T) {
	e := newSiteEnv(t)
	e.startVerification()
	e.api.result = `{"status":"verified","issuer":"did:example:issuer","claims":{"over_18":true}}`

	resp, _ := e.do("GET", "/callback?challenge=chal-1")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/members" {
		t.Fatalf("callback = %d to %q, want a redirect to /members", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := e.do("GET", "/members")
	if resp.StatusCode != 200 || !strings.Contains(body, "Welcome to the members area") || !strings.Contains(body, "over_18") {
		t.Fatalf("members = %d %q", resp.StatusCode, body)
	}
	if resp, _ := e.do("GET", "/"); resp.Header.Get("Location") != "/members" {
		t.Error("the home page should send a verified browser on to the members area")
	}

	e.do("POST", "/signout")
	if resp, _ := e.do("GET", "/members"); resp.Header.Get("Location") != "/" {
		t.Error("after signing out the members area must be closed again")
	}
}

func TestAVerifiedCredentialThatSaysNotOverEighteenIsNotLetIn(t *testing.T) {
	e := newSiteEnv(t)
	e.startVerification()
	e.api.result = `{"status":"verified","claims":{"over_18":false}}`
	e.do("GET", "/callback?challenge=chal-1")

	resp, body := e.do("GET", "/members")
	if resp.StatusCode != http.StatusForbidden || strings.Contains(body, "Welcome") {
		t.Fatalf("members = %d %q, want refused", resp.StatusCode, body)
	}
}

func TestNothingIsGrantedUnlessTheVerifierSaysVerified(t *testing.T) {
	for name, result := range map[string]string{
		"pending":     `{"status":"pending"}`,
		"rejected":    `{"status":"rejected","reason":"revoked"}`,
		"unavailable": `{"status":"unavailable","reason":"verification_unavailable"}`,
		"expired":     `{"status":"expired"}`,
		"unknown":     `{"status":"something-new"}`,
		"garbage":     `not json`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newSiteEnv(t)
			e.startVerification()
			e.api.result = result
			resp, body := e.do("GET", "/callback?challenge=chal-1")
			if resp.StatusCode == http.StatusSeeOther || strings.Contains(body, "Welcome") {
				t.Fatalf("callback = %d %q: a %s verdict let someone in", resp.StatusCode, body, name)
			}
			if resp, _ := e.do("GET", "/members"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
				t.Fatalf("members = %d: still reachable after a %s verdict", resp.StatusCode, name)
			}
		})
	}
}

func TestRejectionShowsTheReasonInPlainLanguage(t *testing.T) {
	e := newSiteEnv(t)
	e.startVerification()
	e.api.result = `{"status":"rejected","reason":"revoked"}`
	resp, body := e.do("GET", "/callback?challenge=chal-1")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "revoked by its issuer") {
		t.Fatalf("callback = %d %q", resp.StatusCode, body)
	}
}

// A challenge id travels through the browser and the wallet's URL: knowing it
// must not be enough to read the result.
func TestOnlyTheBrowserThatStartedItCanReadTheResult(t *testing.T) {
	e := newSiteEnv(t)
	e.startVerification()
	e.api.result = `{"status":"verified","claims":{"over_18":true}}`

	other := newSiteEnv(t) // another browser: no cookie
	other.api = e.api
	if resp, _ := other.do("GET", "/callback?challenge=chal-1"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a browser with no session = %d, want 400", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/callback?challenge=someone-elses"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a challenge id that is not this session's = %d, want 400", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/members"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("members without having read the result = %d, want a redirect", resp.StatusCode)
	}
}

func TestAnUnreachableVerifierMeansNobodyIsLetIn(t *testing.T) {
	e := newSiteEnv(t)
	e.api.down = true
	resp, body := e.do("POST", "/start")
	if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(resp.Header.Get("Location"), "present") {
		t.Fatalf("start with the verifier down = %d to %q %q, want a 503 and no redirect to the wallet", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	e.api.down = false
	e.startVerification()
	e.api.down = true
	if resp, _ := e.do("GET", "/callback?challenge=chal-1"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("callback with the verifier down = %d, want 503", resp.StatusCode)
	}
}

// The session cookie, the wallet and Phantom all go by localhost.
func TestLoopbackIPIsSentToTheConfiguredAddress(t *testing.T) {
	e := newSiteEnv(t)
	resp, err := e.client.Get(e.srv.URL + "/members?x=1") // the test server's own 127.0.0.1 address
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "http://localhost:9090/members?x=1" {
		t.Fatalf("got %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSessionsAreCappedAndExpire(t *testing.T) {
	now := time.Now()
	s := newSessions(2, time.Minute)
	s.now = func() time.Time { return now }
	a, _ := s.create(challenge{ID: "a"})
	if _, err := s.create(challenge{ID: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.create(challenge{ID: "c"}); err == nil {
		t.Fatal("a third session was created over the cap")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := s.get(a); ok {
		t.Fatal("an expired session was still found")
	}
	if _, err := s.create(challenge{ID: "c"}); err != nil {
		t.Fatalf("after the others expired: %v", err)
	}
}
