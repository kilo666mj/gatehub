package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	authModeWebAuthn = "webauthn"
	authModeNone     = "none"

	sessionCookieName           = "gatehub_session"
	loginChallengeCookieName    = "gatehub_login_challenge"
	registerChallengeCookieName = "gatehub_register_challenge"
	nonExpiringSessionCookieAge = 10 * 365 * 24 * 60 * 60
	// WebAuthnID is fixed: gatehub is a single-operator control plane.
	webAuthnUserID = "gatehub-admin"
)

// AuthService gates the admin surface with WebAuthn (passkey) login and
// server-side sessions. It shares the store's SQLite database. When the mode is
// authModeNone it is a pass-through (intended for localhost development only).
type AuthService struct {
	mode          string
	userName      string
	origin        string
	sessionMaxAge int

	db       *sql.DB
	webauthn *webauthn.WebAuthn

	mu         sync.Mutex
	challenges map[string]challengeEntry
}

type challengeEntry struct {
	Session webauthn.SessionData
	Expires time.Time
}

type webAuthnUser struct {
	name        string
	credentials []webauthn.Credential
}

func newAuthService(cfg config, db *sql.DB) (*AuthService, error) {
	svc := &AuthService{
		mode:          cfg.AdminAuth,
		userName:      firstNonEmpty(cfg.AdminUserName, "gatehub admin"),
		origin:        cfg.AdminOrigin,
		sessionMaxAge: cfg.AdminSessionMaxAge,
		challenges:    map[string]challengeEntry{},
	}
	if cfg.AdminAuth != authModeWebAuthn {
		return svc, nil
	}
	svc.db = db
	if err := svc.initDB(); err != nil {
		return nil, err
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.AdminRPID,
		RPDisplayName: firstNonEmpty(cfg.AdminRPName, "gatehub"),
		RPOrigins:     []string{cfg.AdminOrigin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure webauthn: %w", err)
	}
	svc.webauthn = w
	return svc, nil
}

func (a *AuthService) enabled() bool {
	return a.mode == authModeWebAuthn && a.webauthn != nil
}

func (a *AuthService) initDB() error {
	_, err := a.db.Exec(`
CREATE TABLE IF NOT EXISTS webauthn_credential (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	credential_id BLOB NOT NULL UNIQUE,
	credential_json BLOB NOT NULL,
	created_at TEXT NOT NULL
);
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
		authJSON(w, map[string]bool{"registered": false, "authenticated": true})
		return
	}
	registered, err := a.hasCredential()
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	authJSON(w, map[string]bool{
		"registered":    registered,
		"authenticated": a.validRequestSession(r),
	})
}

func (a *AuthService) registerBegin(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		http.NotFound(w, r)
		return
	}
	// First-time setup is open; once a credential exists, only an authenticated
	// operator may enroll additional devices.
	if !a.validRequestSession(r) {
		registered, err := a.hasCredential()
		if err != nil {
			authError(w, err, http.StatusInternalServerError)
			return
		}
		if registered {
			authError(w, errors.New("registration is closed - a credential already exists"), http.StatusForbidden)
			return
		}
	}
	user, err := a.loadUser()
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	creation, session, err := a.webauthn.BeginRegistration(user, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.storeChallenge(w, registerChallengeCookieName, "register", *session); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	authJSON(w, creation)
}

func (a *AuthService) registerComplete(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		http.NotFound(w, r)
		return
	}
	user, err := a.loadUser()
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	requireFirstCredential := !a.validRequestSession(r)
	if requireFirstCredential {
		registered, err := a.hasCredential()
		if err != nil {
			authError(w, err, http.StatusInternalServerError)
			return
		}
		if registered {
			authError(w, errors.New("registration is closed - a credential already exists"), http.StatusForbidden)
			return
		}
	}
	session, err := a.popChallenge(w, r, registerChallengeCookieName, "register")
	if err != nil {
		authError(w, err, http.StatusBadRequest)
		return
	}
	credential, err := a.webauthn.FinishRegistration(user, session, r)
	if err != nil {
		authError(w, fmt.Errorf("registration failed: %w", err), http.StatusBadRequest)
		return
	}
	if err := a.saveCredential(*credential, requireFirstCredential); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.issueSession(w); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	authJSON(w, map[string]string{"status": "registered"})
}

func (a *AuthService) loginBegin(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		http.NotFound(w, r)
		return
	}
	user, err := a.loadUser()
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	if len(user.credentials) == 0 {
		authError(w, errors.New("no credentials registered"), http.StatusNotFound)
		return
	}
	assertion, session, err := a.webauthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.storeChallenge(w, loginChallengeCookieName, "login", *session); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	authJSON(w, assertion)
}

func (a *AuthService) loginComplete(w http.ResponseWriter, r *http.Request) {
	if !a.enabled() {
		http.NotFound(w, r)
		return
	}
	user, err := a.loadUser()
	if err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	session, err := a.popChallenge(w, r, loginChallengeCookieName, "login")
	if err != nil {
		authError(w, err, http.StatusBadRequest)
		return
	}
	credential, err := a.webauthn.FinishLogin(user, session, r)
	if err != nil {
		authError(w, fmt.Errorf("authentication failed: %w", err), http.StatusBadRequest)
		return
	}
	if err := a.saveCredential(*credential, false); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	if err := a.issueSession(w); err != nil {
		authError(w, err, http.StatusInternalServerError)
		return
	}
	authJSON(w, map[string]string{"status": "authenticated"})
}

func (a *AuthService) logout(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	if a.db != nil {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			_, _ = a.db.Exec(`DELETE FROM app_session WHERE token = ?`, cookie.Value)
		}
	}
	a.clearCookie(w, sessionCookieName, "/")
	authJSON(w, map[string]string{"status": "logged out"})
}

func (a *AuthService) storeChallenge(w http.ResponseWriter, cookieName, prefix string, session webauthn.SessionData) error {
	id, err := randomHex(32)
	if err != nil {
		return err
	}
	key := prefix + ":" + id
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, entry := range a.challenges {
		if entry.Expires.Before(now) {
			delete(a.challenges, k)
		}
	}
	a.challenges[key] = challengeEntry{Session: session, Expires: now.Add(120 * time.Second)}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/api/auth/",
		MaxAge:   120,
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.origin, "https://"),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (a *AuthService) popChallenge(w http.ResponseWriter, r *http.Request, cookieName, prefix string) (webauthn.SessionData, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return webauthn.SessionData{}, errors.New("challenge expired or not found - try again")
	}
	key := prefix + ":" + cookie.Value
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.challenges[key]
	if !ok || entry.Expires.Before(time.Now()) {
		return webauthn.SessionData{}, errors.New("challenge expired or not found - try again")
	}
	delete(a.challenges, key)
	a.clearCookie(w, cookieName, "/api/auth/")
	return entry.Session, nil
}

func (a *AuthService) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.origin, "https://"),
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *AuthService) loadUser() (*webAuthnUser, error) {
	credentials, err := a.loadCredentials()
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{name: a.userName, credentials: credentials}, nil
}

func (a *AuthService) loadCredentials() ([]webauthn.Credential, error) {
	rows, err := a.db.Query(`SELECT credential_json FROM webauthn_credential ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}
	defer rows.Close()
	var credentials []webauthn.Credential
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(data, &credential); err != nil {
			return nil, fmt.Errorf("decode credential: %w", err)
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (a *AuthService) saveCredential(credential webauthn.Credential, requireFirstCredential bool) error {
	data, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode credential: %w", err)
	}
	if requireFirstCredential {
		res, err := a.db.Exec(`
INSERT INTO webauthn_credential (credential_id, credential_json, created_at)
SELECT ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM webauthn_credential)`,
			credential.ID, data, nowString())
		if err != nil {
			return fmt.Errorf("save first credential: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("save first credential: %w", err)
		}
		if affected == 0 {
			return errors.New("registration is closed - a credential already exists")
		}
		return nil
	}
	_, err = a.db.Exec(`
INSERT INTO webauthn_credential (credential_id, credential_json, created_at)
VALUES (?, ?, ?)
ON CONFLICT(credential_id) DO UPDATE SET credential_json = excluded.credential_json`,
		credential.ID, data, nowString())
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}
	return nil
}

func (a *AuthService) hasCredential() (bool, error) {
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credential`).Scan(&count); err != nil {
		return false, fmt.Errorf("check credentials: %w", err)
	}
	return count > 0, nil
}

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
		Secure:   strings.HasPrefix(a.origin, "https://"),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

func (u *webAuthnUser) WebAuthnID() []byte          { return []byte(webAuthnUserID) }
func (u *webAuthnUser) WebAuthnName() string        { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string { return u.name }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func authJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func authError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
}
