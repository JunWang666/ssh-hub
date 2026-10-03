package main

import (
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed *.html
var webFiles embed.FS

type Session struct {
	CSRF      string
	ExpiresAt time.Time
}

type App struct {
	store          *Store
	publicURL      string
	adminURL       string
	secureCookie   bool
	setup          sync.Mutex
	setupSecret    string
	sessionsMu     sync.Mutex
	sessions       map[string]Session
	attemptsMu     sync.Mutex
	attempts       map[string]loginAttempt
	registrationMu sync.Mutex
	registrations  map[string]registrationWindow
	oidcMu         sync.Mutex
	oidc           *oidcProvider
	oidcLogins     map[string]oidcLoginState
	index          *template.Template
}

type loginAttempt struct {
	Count      int
	WindowEnds time.Time
	BlockedTo  time.Time
}

type registrationWindow struct {
	Count int
	Ends  time.Time
}

func newApp(store *Store, publicURL string) *App {
	token, _ := randomToken(24)
	t, err := template.ParseFS(webFiles, "login.html")
	if err != nil {
		panic(err)
	}
	return &App{
		store:         store,
		publicURL:     publicURL,
		secureCookie:  strings.HasPrefix(publicURL, "https://"),
		setupSecret:   token,
		sessions:      map[string]Session{},
		attempts:      map[string]loginAttempt{},
		registrations: map[string]registrationWindow{},
		oidcLogins:    map[string]oidcLoginState{},
		index:         t,
	}
}

func validatePublicURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("must be an origin URL such as https://mcp.example.com")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("scheme must be http or https")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return errors.New("http is only allowed for localhost; use HTTPS for remote deployments")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *App) setupToken() string {
	a.setup.Lock()
	defer a.setup.Unlock()
	var passwordHash string
	_ = a.store.view(func(state State) error { passwordHash = state.PasswordHash; return nil })
	if passwordHash != "" {
		return ""
	}
	return a.setupSecret
}

func (a *App) setInitialPassword(password string) error {
	if len(password) < 12 {
		return errors.New("administrator password must be at least 12 characters")
	}
	hash, err := createPasswordHash(password)
	if err != nil {
		return err
	}
	err = a.store.update(func(state *State) error {
		if state.PasswordHash == "" {
			state.PasswordHash = hash
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.setup.Lock()
	a.setupSecret = ""
	a.setup.Unlock()
	return nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /ui", a.handleUI)
	mux.HandleFunc("GET /login", a.handleLoginGet)
	mux.HandleFunc("POST /login", a.handleLoginPost)
	mux.HandleFunc("GET /auth/oidc", a.handleOIDCStart)
	mux.HandleFunc("GET /auth/oidc/callback", a.handleOIDCCallback)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleAuthorizationMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", a.handleResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", a.handleResourceMetadata)
	mux.HandleFunc("POST /oauth/register", a.handleRegistration)
	mux.HandleFunc("GET /oauth/authorize", a.handleAuthorizeGet)
	mux.HandleFunc("POST /oauth/authorize", a.handleAuthorizePost)
	mux.HandleFunc("POST /oauth/token", a.handleToken)
	mux.HandleFunc("POST /oauth/revoke", a.handleRevoke)
	mux.HandleFunc("GET /api/overview", a.handleOverview)
	mux.HandleFunc("POST /api/keys", a.handleCreateKey)
	mux.HandleFunc("DELETE /api/keys/{id}", a.handleDeleteKey)
	mux.HandleFunc("POST /api/hosts", a.handleCreateHost)
	mux.HandleFunc("DELETE /api/hosts/{id}", a.handleDeleteHost)
	mux.HandleFunc("DELETE /api/clients/{id}", a.handleDeleteClient)
	mux.HandleFunc("GET /mcp", a.handleMCP)
	mux.HandleFunc("POST /mcp", a.handleMCP)
	return a.securityHeaders(mux)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !a.validRequestHost(r.Host) {
			http.Error(w, "host not allowed", http.StatusMisdirectedRequest)
			return
		}
		if a.adminURL != "" && hostMatchesOrigin(r.Host, a.publicURL) && !publicMCPPathAllowed(r.Method, r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// Native POST forms need their same-origin Origin header for CSRF
		// validation; no-referrer makes browsers serialize it as "null".
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		if a.secureCookie {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) validRequestHost(host string) bool {
	return hostMatchesOrigin(host, a.publicURL) || hostMatchesOrigin(host, a.adminURL)
}

func (a *App) validSameOrigin(origin, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	for _, configuredOrigin := range []string{a.publicURL, a.adminURL} {
		configured, err := url.Parse(configuredOrigin)
		if err != nil || configured.Scheme != parsed.Scheme {
			continue
		}
		if hostMatchesOrigin(parsed.Host, configuredOrigin) && hostMatchesOrigin(requestHost, configuredOrigin) {
			return true
		}
	}
	return false
}

func hostMatchesOrigin(host, origin string) bool {
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	expectedHost, expectedPort := hostPort(parsed.Host, parsed.Scheme)
	actualHost, actualPort := hostPort(host, parsed.Scheme)
	return expectedHost != "" && expectedPort == actualPort && (strings.EqualFold(strings.TrimSuffix(expectedHost, "."), strings.TrimSuffix(actualHost, ".")) ||
		isLoopbackHost(expectedHost) && isLoopbackHost(actualHost))
}

func publicMCPPathAllowed(method, path string) bool {
	switch path {
	case "/mcp":
		return method == http.MethodGet || method == http.MethodPost
	case "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		return method == http.MethodGet
	case "/oauth/register", "/oauth/token", "/oauth/revoke":
		return method == http.MethodPost
	case "/oauth/authorize":
		return method == http.MethodGet || method == http.MethodPost
	case "/login":
		return method == http.MethodGet || method == http.MethodPost
	case "/auth/oidc", "/auth/oidc/callback":
		return method == http.MethodGet
	default:
		return false
	}
}

func (a *App) allowClientRegistration(ip string) bool {
	now := time.Now()
	a.registrationMu.Lock()
	defer a.registrationMu.Unlock()
	window := a.registrations[ip]
	if now.After(window.Ends) {
		window = registrationWindow{Ends: now.Add(time.Hour)}
	}
	if window.Count >= 30 {
		a.registrations[ip] = window
		return false
	}
	window.Count++
	a.registrations[ip] = window
	return true
}

func hostPort(host, scheme string) (string, string) {
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Hostname() == "" {
		return "", ""
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", ""
	}
	return parsed.Hostname(), port
}

func (a *App) currentSession(r *http.Request) (string, Session, bool) {
	cookie, err := r.Cookie("ssh_hub_session")
	if err != nil || cookie.Value == "" {
		return "", Session{}, false
	}
	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()
	session, ok := a.sessions[cookie.Value]
	if !ok || time.Now().After(session.ExpiresAt) {
		delete(a.sessions, cookie.Value)
		return "", Session{}, false
	}
	return cookie.Value, session, true
}

func (a *App) createSession(w http.ResponseWriter) (Session, error) {
	key, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return Session{}, err
	}
	session := Session{CSRF: csrf, ExpiresAt: time.Now().Add(12 * time.Hour)}
	a.sessionsMu.Lock()
	for oldKey, old := range a.sessions {
		if time.Now().After(old.ExpiresAt) {
			delete(a.sessions, oldKey)
		}
	}
	a.sessions[key] = session
	a.sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "ssh_hub_session", Value: key, Path: "/", HttpOnly: true,
		Secure: a.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 60 * 60,
	})
	return session, nil
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	_, session, ok := a.currentSession(r)
	if !ok {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
		} else {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(safeAuthorizePath(r)), http.StatusSeeOther)
		}
		return Session{}, false
	}
	return session, true
}

func (a *App) checkCSRF(w http.ResponseWriter, r *http.Request) (Session, bool) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return Session{}, false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(session.CSRF)) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return Session{}, false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if !a.validSameOrigin(origin, r.Host) {
			log.Printf("CSRF Origin rejected: method=%s path=%q host=%q origin=%q", r.Method, r.URL.Path, r.Host, origin)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin check failed"})
			return Session{}, false
		}
	}
	return session, true
}

func safeAuthorizePath(r *http.Request) string {
	if r.URL.Path == "/oauth/authorize" {
		return r.URL.RequestURI()
	}
	return "/ui"
}

func safeNext(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/oauth/authorize" || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return "/ui"
	}
	return u.RequestURI()
}

func (a *App) handleUI(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := template.Must(template.ParseFS(webFiles, "index.html")).Execute(w, map[string]string{
		"CSRF": session.CSRF, "MCPURL": a.publicURL + "/mcp",
		"ResourceURL": a.publicURL + "/mcp", "PublicURL": a.publicURL,
	}); err != nil {
		return
	}
}
