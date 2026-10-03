package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestOIDCIdentityAllowlist(t *testing.T) {
	allowedEmails := parseOIDCAllowlist("admin@example.com, other@example.com", true)
	allowedSubjects := parseOIDCAllowlist("tenant|admin-123", false)

	tests := []struct {
		name   string
		claims oidcClaims
		want   bool
	}{
		{
			name:   "verified email matches without case sensitivity",
			claims: oidcClaims{Subject: "user-1", Email: "Admin@Example.com", EmailVerified: true},
			want:   true,
		},
		{
			name:   "unverified email is not accepted",
			claims: oidcClaims{Subject: "user-1", Email: "admin@example.com"},
			want:   false,
		},
		{
			name:   "exact subject is accepted independently of email verification",
			claims: oidcClaims{Subject: "tenant|admin-123", Email: "other@example.com"},
			want:   true,
		},
		{
			name:   "subject matching is exact",
			claims: oidcClaims{Subject: "Tenant|admin-123", Email: "other@example.com"},
			want:   false,
		},
		{
			name:   "unlisted identity is rejected",
			claims: oidcClaims{Subject: "user-2", Email: "guest@example.com", EmailVerified: true},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := oidcIdentityAllowed(tt.claims, allowedEmails, allowedSubjects); got != tt.want {
				t.Fatalf("oidcIdentityAllowed() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestValidateOIDCIssuer(t *testing.T) {
	for _, tt := range []struct {
		issuer string
		valid  bool
	}{
		{issuer: "https://id.example.com/realms/ssh-hub", valid: true},
		{issuer: "http://localhost:8081/realms/ssh-hub", valid: true},
		{issuer: "http://id.example.com/realms/ssh-hub", valid: false},
		{issuer: "https://user:pass@id.example.com", valid: false},
		{issuer: "https://id.example.com?tenant=other", valid: false},
	} {
		err := validateOIDCIssuer(tt.issuer)
		if (err == nil) != tt.valid {
			t.Errorf("validateOIDCIssuer(%q) error = %v, want valid=%t", tt.issuer, err, tt.valid)
		}
	}
}

func TestAdminOriginIsAllowedSeparatelyFromPublicOrigin(t *testing.T) {
	app := &App{publicURL: "https://sshhub.example.test", adminURL: "https://sshadmin.example.test"}
	tests := []struct {
		host string
		want bool
	}{
		{host: "sshhub.example.test", want: true},
		{host: "sshadmin.example.test", want: true},
		{host: "untrusted.example.test", want: false},
		{host: "sshadmin.example.test:8443", want: false},
	}
	for _, tt := range tests {
		if got := app.validRequestHost(tt.host); got != tt.want {
			t.Errorf("validRequestHost(%q) = %t, want %t", tt.host, got, tt.want)
		}
	}
	if got := app.oidcRedirectURL("sshhub.example.test"); got != "https://sshhub.example.test"+oidcCallbackPath {
		t.Errorf("public OIDC redirect = %q", got)
	}
	if got := app.oidcRedirectURL("sshadmin.example.test"); got != "https://sshadmin.example.test"+oidcCallbackPath {
		t.Errorf("admin OIDC redirect = %q", got)
	}
}

func TestPublicOriginHidesManagementRoutesWhenAdminOriginIsConfigured(t *testing.T) {
	app := &App{publicURL: "https://sshhub.example.test", adminURL: "https://sshadmin.example.test"}
	handler := app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	tests := []struct {
		name   string
		host   string
		method string
		path   string
		want   int
	}{
		{name: "MCP POST", host: "sshhub.example.test", method: http.MethodPost, path: "/mcp", want: http.StatusNoContent},
		{name: "MCP GET", host: "sshhub.example.test", method: http.MethodGet, path: "/mcp", want: http.StatusNoContent},
		{name: "OAuth metadata", host: "sshhub.example.test", method: http.MethodGet, path: "/.well-known/oauth-authorization-server", want: http.StatusNoContent},
		{name: "DCR", host: "sshhub.example.test", method: http.MethodPost, path: "/oauth/register", want: http.StatusNoContent},
		{name: "authorization page", host: "sshhub.example.test", method: http.MethodGet, path: "/oauth/authorize", want: http.StatusNoContent},
		{name: "login page", host: "sshhub.example.test", method: http.MethodGet, path: "/login", want: http.StatusNoContent},
		{name: "admin UI hidden", host: "sshhub.example.test", method: http.MethodGet, path: "/ui", want: http.StatusNotFound},
		{name: "admin API hidden", host: "sshhub.example.test", method: http.MethodGet, path: "/api/overview", want: http.StatusNotFound},
		{name: "logout hidden", host: "sshhub.example.test", method: http.MethodPost, path: "/logout", want: http.StatusNotFound},
		{name: "wrong method hidden", host: "sshhub.example.test", method: http.MethodGet, path: "/oauth/token", want: http.StatusNotFound},
		{name: "admin UI allowed on admin host", host: "sshadmin.example.test", method: http.MethodGet, path: "/ui", want: http.StatusNoContent},
		{name: "unknown host rejected", host: "untrusted.example.test", method: http.MethodGet, path: "/ui", want: http.StatusMisdirectedRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.path, nil)
			request.Host = tt.host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.want {
				t.Fatalf("status = %d, want %d", response.Code, tt.want)
			}
		})
	}
}

func TestOIDCLoginUsesPKCEAndCreatesSession(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://issuer.example.test"
	transport := &oidcTestTransport{issuer: issuer, privateKey: privateKey}

	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(store, "https://sshhub.example.test")
	app.adminURL = "https://sshadmin.example.test"
	if err := app.configureOIDCWithHTTPClient(oidcSettings{
		Issuer: issuer, ClientID: "ssh-hub-client", ClientSecret: "test-secret",
		AllowedEmails: "admin@example.com",
	}, &http.Client{Transport: transport, Timeout: 15 * time.Second}); err != nil {
		t.Fatal(err)
	}
	handler := app.routes()

	startRequest := httptest.NewRequest(http.MethodGet, "/auth/oidc?next=%2Fui", nil)
	startRequest.Host = "sshadmin.example.test"
	startResponse := httptest.NewRecorder()
	handler.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusSeeOther {
		t.Fatalf("OIDC start status = %d, want %d", startResponse.Code, http.StatusSeeOther)
	}
	authURL, err := url.Parse(startResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := authURL.Query()
	if got := query.Get("redirect_uri"); got != app.adminURL+oidcCallbackPath {
		t.Fatalf("OIDC redirect_uri = %q, want admin callback", got)
	}
	state := query.Get("state")
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE method = %q, want S256", query.Get("code_challenge_method"))
	}
	app.oidcMu.Lock()
	pending := app.oidcLogins[state]
	app.oidcMu.Unlock()
	if state == "" || pending.Verifier == "" || query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(pending.Verifier) {
		t.Fatal("OIDC authorization request did not bind state to an S256 PKCE verifier")
	}
	if query.Get("nonce") != pending.Nonce {
		t.Fatal("OIDC authorization request did not include the expected nonce")
	}

	claims := map[string]any{
		"iss": issuer, "sub": "admin-123", "aud": "ssh-hub-client",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"nonce": pending.Nonce, "email": "admin@example.com", "email_verified": true,
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(encodedClaims)
	unsignedToken := header + "." + payload
	digest := sha256.Sum256([]byte(unsignedToken))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	transport.idToken = unsignedToken + "." + base64.RawURLEncoding.EncodeToString(signature)
	transport.mu.Unlock()

	callbackQuery := url.Values{"state": {state}, "code": {"test-code"}}
	callbackRequest := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?"+callbackQuery.Encode(), nil)
	callbackRequest.Host = "sshadmin.example.test"
	for _, cookie := range startResponse.Result().Cookies() {
		callbackRequest.AddCookie(cookie)
	}
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusSeeOther || callbackResponse.Header().Get("Location") != "/ui" {
		t.Fatalf("OIDC callback response = %d %q, want redirect to /ui", callbackResponse.Code, callbackResponse.Header().Get("Location"))
	}
	transport.mu.Lock()
	verifier := transport.codeVerifier
	redirectURI := transport.redirectURI
	transport.mu.Unlock()
	if verifier != pending.Verifier {
		t.Fatalf("token exchange PKCE verifier = %q, want %q", verifier, pending.Verifier)
	}
	if redirectURI != app.adminURL+oidcCallbackPath {
		t.Fatalf("token exchange redirect_uri = %q, want admin callback", redirectURI)
	}
	foundSession := false
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == "ssh_hub_session" && cookie.Value != "" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("successful OIDC callback did not create a session")
	}
}

type oidcTestTransport struct {
	issuer       string
	privateKey   *rsa.PrivateKey
	mu           sync.Mutex
	idToken      string
	codeVerifier string
	redirectURI  string
}

func (f *oidcTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var status int
	var body string
	switch req.URL.Path {
	case "/.well-known/openid-configuration":
		metadata, err := json.Marshal(map[string]any{
			"issuer": f.issuer, "authorization_endpoint": f.issuer + "/authorize",
			"token_endpoint": f.issuer + "/token", "jwks_uri": f.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
		if err != nil {
			return nil, err
		}
		status, body = http.StatusOK, string(metadata)
	case "/token":
		requestBody, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(requestBody))
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.codeVerifier = form.Get("code_verifier")
		f.redirectURI = form.Get("redirect_uri")
		idToken := f.idToken
		f.mu.Unlock()
		tokenResponse, err := json.Marshal(map[string]any{
			"access_token": "test-access-token", "token_type": "Bearer",
			"expires_in": 3600, "id_token": idToken,
		})
		if err != nil {
			return nil, err
		}
		status, body = http.StatusOK, string(tokenResponse)
	case "/jwks":
		publicKey := &f.privateKey.PublicKey
		keys, err := json.Marshal(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}}})
		if err != nil {
			return nil, err
		}
		status, body = http.StatusOK, string(keys)
	default:
		status, body = http.StatusNotFound, "not found"
	}
	response := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
	response.Header.Set("Content-Type", "application/json")
	return response, nil
}
