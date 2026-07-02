package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func newTestAuth(t *testing.T, mode string) *AuthService {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "auth.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config{
		AdminAuth:   mode,
		AdminRPID:   "gatehub.example.com",
		AdminOrigin: "https://gatehub.example.com",
	}
	auth, err := newAuthService(cfg, store.db)
	if err != nil {
		t.Fatalf("newAuthService: %v", err)
	}
	return auth
}

func TestRequireModeNonePassesThrough(t *testing.T) {
	auth := newTestAuth(t, authModeNone)
	called := false
	h := auth.require(func(w http.ResponseWriter, r *http.Request) { called = true })
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("handler was not called in none mode")
	}
}

func TestRequireBlocksUnauthenticated(t *testing.T) {
	auth := newTestAuth(t, authModeWebAuthn)
	next := func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler should not run unauthenticated") }

	// GET page redirects to /login.
	rec := httptest.NewRecorder()
	auth.require(next)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("GET / = %d loc=%q, want 302 -> /login", rec.Code, rec.Header().Get("Location"))
	}

	// POST returns 401.
	rec = httptest.NewRecorder()
	auth.require(next)(rec, httptest.NewRequest(http.MethodPost, "/decisions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /decisions = %d, want 401", rec.Code)
	}

	// API GET returns 401 rather than redirect.
	rec = httptest.NewRecorder()
	auth.require(next)(rec, httptest.NewRequest(http.MethodGet, "/api/fingerprints", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/fingerprints = %d, want 401", rec.Code)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	auth := newTestAuth(t, authModeWebAuthn)

	rec := httptest.NewRecorder()
	if err := auth.issueSession(rec); err != nil {
		t.Fatalf("issueSession: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("expected session cookie, got %+v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || !cookies[0].Secure {
		t.Fatalf("cookie hardening missing: %+v", cookies[0])
	}

	authed := httptest.NewRequest(http.MethodGet, "/", nil)
	authed.AddCookie(cookies[0])
	if !auth.validRequestSession(authed) {
		t.Fatal("validRequestSession = false for issued session")
	}

	// A gated handler now runs with the session cookie present.
	called := false
	rec2 := httptest.NewRecorder()
	auth.require(func(w http.ResponseWriter, r *http.Request) { called = true })(rec2, authed)
	if !called {
		t.Fatal("authenticated request did not reach handler")
	}

	// Bogus token is rejected.
	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "deadbeef"})
	if auth.validRequestSession(bad) {
		t.Fatal("validRequestSession = true for unknown token")
	}
}

func TestRequireCSRF(t *testing.T) {
	auth := newTestAuth(t, authModeWebAuthn)

	rec := httptest.NewRecorder()
	if err := auth.issueSession(rec); err != nil {
		t.Fatalf("issueSession: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader("csrf_token=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	if auth.requireCSRF(httptest.NewRecorder(), req) {
		t.Fatal("requireCSRF accepted a bad token")
	}

	tokenReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tokenReq.AddCookie(cookie)
	token := auth.csrfToken(tokenReq)
	req = httptest.NewRequest(http.MethodPost, "/decisions", strings.NewReader("csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	if !auth.requireCSRF(httptest.NewRecorder(), req) {
		t.Fatal("requireCSRF rejected the stored token")
	}
}

func TestChallengeCookiesArePerFlow(t *testing.T) {
	auth := newTestAuth(t, authModeWebAuthn)

	rec1 := httptest.NewRecorder()
	if err := auth.storeChallenge(rec1, loginChallengeCookieName, "login", webauthn.SessionData{}); err != nil {
		t.Fatalf("storeChallenge 1: %v", err)
	}
	rec2 := httptest.NewRecorder()
	if err := auth.storeChallenge(rec2, loginChallengeCookieName, "login", webauthn.SessionData{}); err != nil {
		t.Fatalf("storeChallenge 2: %v", err)
	}
	cookie1 := rec1.Result().Cookies()[0]
	cookie2 := rec2.Result().Cookies()[0]
	if cookie1.Value == cookie2.Value {
		t.Fatal("challenge IDs should be unique")
	}

	req1 := httptest.NewRequest(http.MethodPost, "/api/auth/login/complete", nil)
	req1.AddCookie(cookie1)
	if _, err := auth.popChallenge(httptest.NewRecorder(), req1, loginChallengeCookieName, "login"); err != nil {
		t.Fatalf("first challenge was overwritten: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/login/complete", nil)
	req2.AddCookie(cookie2)
	if _, err := auth.popChallenge(httptest.NewRecorder(), req2, loginChallengeCookieName, "login"); err != nil {
		t.Fatalf("second challenge missing: %v", err)
	}
}

func TestRegisterClosedAfterCredentialExists(t *testing.T) {
	auth := newTestAuth(t, authModeWebAuthn)
	// Simulate an existing enrolled credential.
	if _, err := auth.db.Exec(
		`INSERT INTO webauthn_credential (credential_id, credential_json, created_at) VALUES (?, ?, ?)`,
		[]byte("cred-1"), []byte("{}"), nowString(),
	); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	rec := httptest.NewRecorder()
	auth.registerBegin(rec, httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("registerBegin with existing credential = %d, want 403", rec.Code)
	}
}
