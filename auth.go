package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/oidcrp"
)

const (
	authModeOIDC = "oidc"
	authModeNone = "none"

	sessionCookieName           = "gatehub_session"
	oidcStateCookieName         = "gatehub_oidc"
	nonExpiringSessionCookieAge = 10 * 365 * 24 * 60 * 60
)

// AuthService gates the admin surface with OpenID Connect (e.g. Pocket ID) login
// and server-side sessions. It shares the store's SQLite database and delegates
// the browser OIDC flow to the shared oidcrp module, implementing its
// SessionManager for durable sessions. When the mode is authModeNone it is a
// pass-through (intended for localhost development only).
type AuthService struct {
	mode          string
	sessionMaxAge int

	db   *sql.DB
	oidc *oidcrp.Service
}

func newAuthService(cfg config, db *sql.DB) (*AuthService, error) {
	svc := &AuthService{
		mode:          cfg.AdminAuth,
		sessionMaxAge: cfg.AdminSessionMaxAge,
	}
	svc.oidc = oidcrp.New(oidcrp.Config{
		Issuer:          cfg.AdminOIDCIssuer,
		ClientID:        cfg.AdminOIDCClientID,
		ClientSecret:    cfg.AdminOIDCClientSecret,
		RedirectURL:     cfg.AdminOIDCRedirectURL,
		Scopes:          splitList(cfg.AdminOIDCScopes),
		AllowedSubjects: splitList(cfg.AdminOIDCAllowedSubjects),
		AllowedEmails:   splitList(cfg.AdminOIDCAllowedEmails),
		AllowedGroups:   splitList(cfg.AdminOIDCAllowedGroups),
		StateCookieName: oidcStateCookieName,
		LoginPath:       "/login",
		SuccessPath:     "/",
		APIPrefixes:     []string{"/api/"},
	}, svc)
	if cfg.AdminAuth != authModeOIDC {
		return svc, nil
	}
	svc.db = db
	if err := svc.initDB(); err != nil {
		return nil, err
	}
	return svc, nil
}

func (a *AuthService) enabled() bool {
	return a.mode == authModeOIDC && a.db != nil && a.oidc.Enabled()
}

func (a *AuthService) initDB() error {
	_, err := a.db.Exec(`
CREATE TABLE IF NOT EXISTS app_session (
	token TEXT PRIMARY KEY,
	csrf_token TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("initialize auth tables: %w", err)
	}
	if err := addColumnIfMissing(a.db, "app_session", "csrf_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

// ── oidcrp.SessionManager ───────────────────────────────────────────────────

// Valid reports whether the request carries a live session.
func (a *AuthService) Valid(r *http.Request) bool { return a.validRequestSession(r) }

// Issue mints a local session after a verified OIDC login. gatehub is a
// single-operator control plane, so the identity is gated by the allowlist in
// oidcrp and not stored per-session.
func (a *AuthService) Issue(w http.ResponseWriter, _ *http.Request, _ oidcrp.Identity) error {
	return a.issueSession(w)
}

// Clear deletes the current session and expires its cookie.
func (a *AuthService) Clear(w http.ResponseWriter, r *http.Request) {
	if a.db != nil {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			_, _ = a.db.Exec(`DELETE FROM app_session WHERE token = ?`, cookie.Value)
		}
	}
	a.clearCookie(w, sessionCookieName, "/")
}

// ── HTTP handlers ───────────────────────────────────────────────────────────

// require wraps an admin handler, enforcing a valid session. GET page requests
// are redirected to /login; API and non-GET requests get a 401.
func (a *AuthService) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled() {
			next(w, r)
			return
		}
		if a.validRequestSession(r) {
			next(w, r)
			return
		}
		if r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func (a *AuthService) loginPage(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if a.validRequestSession(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginTemplate))
}

func (a *AuthService) status(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		authJSON(w, map[string]bool{"authenticated": true})
		return
	}
	authJSON(w, map[string]bool{"authenticated": a.validRequestSession(r)})
}

// loginStart and callback delegate the browser OIDC flow to oidcrp.
func (a *AuthService) loginStart(w http.ResponseWriter, r *http.Request) { a.oidc.LoginStart(w, r) }
func (a *AuthService) callback(w http.ResponseWriter, r *http.Request)   { a.oidc.Callback(w, r) }

func (a *AuthService) logout(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	a.Clear(w, r)
	authJSON(w, map[string]string{"status": "logged out"})
}

// ── Sessions ────────────────────────────────────────────────────────────────

func (a *AuthService) issueSession(w http.ResponseWriter) error {
	token, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	csrfToken, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("generate csrf token: %w", err)
	}
	now := time.Now().UTC()
	expiresRaw := ""
	cookieMaxAge := nonExpiringSessionCookieAge
	if a.sessionMaxAge > 0 {
		expiresRaw = now.Add(time.Duration(a.sessionMaxAge) * time.Second).Format(time.RFC3339)
		cookieMaxAge = a.sessionMaxAge
	}
	if _, err := a.db.Exec(`INSERT INTO app_session (token, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?)`, token, csrfToken, now.Format(time.RFC3339), expiresRaw); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   a.oidc.SecureCookies(),
		// Lax (not Strict) so the cookie survives the top-level redirect back
		// from the identity provider. Cross-site POSTs are still gated by CSRF.
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (a *AuthService) validRequestSession(r *http.Request) bool {
	if a.db == nil {
		return false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	var expiresRaw string
	err = a.db.QueryRow(`SELECT expires_at FROM app_session WHERE token = ?`, cookie.Value).Scan(&expiresRaw)
	if err != nil {
		return false
	}
	if expiresRaw == "" {
		return true
	}
	expires, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil || expires.Before(time.Now().UTC()) {
		_, _ = a.db.Exec(`DELETE FROM app_session WHERE token = ?`, cookie.Value)
		return false
	}
	return true
}

func (a *AuthService) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.oidc.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

// ── CSRF ────────────────────────────────────────────────────────────────────

func (a *AuthService) csrfToken(r *http.Request) string {
	if !a.enabled() {
		return ""
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	var token string
	if err := a.db.QueryRow(`SELECT csrf_token FROM app_session WHERE token = ?`, cookie.Value).Scan(&token); err != nil {
		return ""
	}
	return token
}

func (a *AuthService) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !a.enabled() {
		return true
	}
	if !a.validRequestSession(r) {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return false
	}
	want := a.csrfToken(r)
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.FormValue("csrf_token")
	}
	if want == "" || got == "" || constantTimeStringEqual(want, got) != 1 {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
}

func constantTimeStringEqual(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// splitList parses a comma-separated flag value into a trimmed, non-empty slice.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func authJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
