package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	accessTokenLifetime  = time.Hour
	refreshTokenLifetime = 30 * 24 * time.Hour
)

func (a *App) handleAuthorizationMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         a.publicURL,
		"authorization_endpoint":                         a.publicURL + "/oauth/authorize",
		"token_endpoint":                                 a.publicURL + "/oauth/token",
		"registration_endpoint":                          a.publicURL + "/oauth/register",
		"revocation_endpoint":                            a.publicURL + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", deviceGrantType},
		"device_authorization_endpoint":                  a.publicURL + "/oauth/device/code",
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{"mcp"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (a *App) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 a.publicURL + "/mcp",
		"authorization_servers":    []string{a.publicURL},
		"scopes_supported":         []string{"mcp"},
		"bearer_methods_supported": []string{"header"},
	})
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

func (a *App) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if !a.allowClientRegistration(clientIP(r.RemoteAddr)) {
		oauthError(w, http.StatusTooManyRequests, "too_many_requests", "client registration limit reached; try again later")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var request registrationRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "request must be a valid JSON object")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "request must contain exactly one JSON object")
		return
	}
	deviceOnly := hasValue(request.GrantTypes, deviceGrantType) && !hasValue(request.GrantTypes, "authorization_code")
	if (len(request.RedirectURIs) == 0 && !deviceOnly) || len(request.RedirectURIs) > 32 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "one to 32 redirect_uris are required")
		return
	}
	request.ClientName = strings.TrimSpace(request.ClientName)
	if request.ClientName == "" {
		request.ClientName = "MCP client"
	}
	if len(request.ClientName) > 128 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name must be at most 128 characters")
		return
	}
	if request.TokenEndpointAuthMethod != "" && request.TokenEndpointAuthMethod != "none" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients using token_endpoint_auth_method=none are supported")
		return
	}
	if request.Scope != "" && request.Scope != "mcp" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only the mcp scope is supported")
		return
	}
	if !onlyAllowedValues(request.GrantTypes, "authorization_code", "refresh_token", deviceGrantType) || !onlyAllowedValues(request.ResponseTypes, "code") || (len(request.GrantTypes) > 0 && !hasValue(request.GrantTypes, "authorization_code") && !hasValue(request.GrantTypes, deviceGrantType)) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only authorization_code, optional refresh_token, and code response are supported")
		return
	}
	seen := make(map[string]bool, len(request.RedirectURIs))
	for _, redirectURI := range request.RedirectURIs {
		if seen[redirectURI] || !validRedirectURI(redirectURI) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be unique HTTPS or localhost URIs without fragments")
			return
		}
		seen[redirectURI] = true
	}
	clientID, err := randomToken(24)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not create client")
		return
	}
	client := OAuthClient{DeviceEnabled: hasValue(request.GrantTypes, deviceGrantType), HostAccessConfigured: true, RequireApproval: true, ID: clientID, Name: request.ClientName, RedirectURIs: request.RedirectURIs, RefreshEnabled: hasValue(request.GrantTypes, "refresh_token"), CreatedAt: time.Now().UTC()}
	err = a.store.update(func(state *State) error {
		if len(state.Clients) >= 2000 {
			return fmt.Errorf("client registration limit reached")
		}
		state.Clients[client.ID] = client
		return nil
	})
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "client registration is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  client.ID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                clientGrantTypes(client),
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      "mcp",
	})
}

func onlyAllowedValues(values []string, allowed ...string) bool {
	for _, value := range values {
		if !hasValue(allowed, value) {
			return false
		}
	}
	return true
}

func hasValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func clientGrantTypes(client OAuthClient) []string {
	grants := []string{}
	if len(client.RedirectURIs) > 0 || !client.DeviceEnabled {
		grants = append(grants, "authorization_code")
	}
	if client.DeviceEnabled {
		grants = append(grants, deviceGrantType)
	}
	if client.RefreshEnabled {
		grants = append(grants, "refresh_token")
	}
	return grants
}

func validRedirectURI(value string) bool {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

func (a *App) authorizeValues(values url.Values) (OAuthClient, AuthCode, bool) {
	responseType := values.Get("response_type")
	clientID := values.Get("client_id")
	redirectURI := values.Get("redirect_uri")
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	resource := a.defaultResource(values.Get("resource"))
	stateValue := values.Get("state")
	scope := values.Get("scope")
	if responseType != "code" || clientID == "" || redirectURI == "" || stateValue == "" || method != "S256" || !validPKCEChallenge(challenge) || !a.resourceIsValid(resource) {
		return OAuthClient{}, AuthCode{}, false
	}
	if scope != "" && scope != "mcp" {
		return OAuthClient{}, AuthCode{}, false
	}
	var client OAuthClient
	err := a.store.view(func(data State) error {
		client, _ = data.Clients[clientID]
		return nil
	})
	if err != nil || client.ID == "" {
		return OAuthClient{}, AuthCode{}, false
	}
	registered := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			registered = true
			break
		}
	}
	if !registered {
		return OAuthClient{}, AuthCode{}, false
	}
	if scope == "" {
		scope = "mcp"
	}
	return client, AuthCode{
		ClientID: clientID, RedirectURI: redirectURI, Challenge: challenge,
		Scope: scope, Resource: resource, ExpiresAt: time.Now().Add(5 * time.Minute),
	}, true
}

func (a *App) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	client, code, ok := a.authorizeValues(r.URL.Query())
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_request", "authorization request is invalid; check client, redirect_uri, resource and S256 PKCE parameters")
		return
	}
	_, session, loggedIn := a.currentSession(r)
	if !loggedIn {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	a.renderConsent(w, client, code, r.URL.Query().Get("state"), session.CSRF)
}

func (a *App) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "authorization request is invalid")
		return
	}
	_, ok := a.checkCSRF(w, r)
	if !ok {
		return
	}
	_, code, valid := a.authorizeValues(r.PostForm)
	if !valid {
		oauthError(w, http.StatusBadRequest, "invalid_request", "authorization request is invalid")
		return
	}
	callback, err := url.Parse(code.RedirectURI)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect URI is invalid")
		return
	}
	stateValue := r.PostForm.Get("state")
	if r.PostForm.Get("decision") != "approve" {
		query := callback.Query()
		query.Set("error", "access_denied")
		query.Set("error_description", "The resource owner denied the request")
		query.Set("state", stateValue)
		query.Set("iss", a.publicURL)
		callback.RawQuery = query.Encode()
		http.Redirect(w, r, callback.String(), http.StatusSeeOther)
		return
	}
	plainCode, err := randomToken(32)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue authorization code")
		return
	}
	code.ExpiresAt = time.Now().Add(5 * time.Minute)
	err = a.store.update(func(state *State) error {
		pruneOAuthState(state, time.Now())
		state.Codes[tokenDigest(plainCode)] = code
		return nil
	})
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "could not issue authorization code")
		return
	}
	query := callback.Query()
	query.Set("code", plainCode)
	query.Set("state", stateValue)
	query.Set("iss", a.publicURL)
	callback.RawQuery = query.Encode()
	http.Redirect(w, r, callback.String(), http.StatusSeeOther)
}

func (a *App) renderConsent(w http.ResponseWriter, client OAuthClient, code AuthCode, stateValue, csrf string) {
	page := template.Must(template.ParseFS(webFiles, "consent.html"))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]string{
		"ClientName": client.Name, "ClientID": client.ID,
		"RedirectURI": code.RedirectURI, "Challenge": code.Challenge,
		"Resource": code.Resource, "Scope": code.Scope,
		"State": stateValue, "CSRF": csrf,
	})
}

func (a *App) defaultResource(value string) string {
	if value == "" {
		return a.publicURL + "/mcp"
	}
	return value
}

func (a *App) resourceIsValid(value string) bool {
	return value == a.publicURL+"/mcp" || value == a.publicURL
}

func validPKCEChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token request is invalid")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		a.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		a.handleRefreshTokenGrant(w, r)
	case deviceGrantType:
		a.handleDeviceToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func (a *App) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostForm.Get("client_id")
	codeValue := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	resource := r.PostForm.Get("resource")
	if clientID == "" || codeValue == "" || redirectURI == "" || !validPKCEVerifier(verifier) || (resource != "" && !a.resourceIsValid(resource)) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token request is incomplete")
		return
	}
	plainToken, err := randomToken(32)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	plainRefresh, err := randomToken(32)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
		return
	}
	now := time.Now()
	token := AccessToken{ClientID: clientID, Scope: "mcp", Resource: resource, ExpiresAt: now.Add(accessTokenLifetime)}
	expectedChallenge := pkceChallenge(verifier)
	valid := false
	refreshEnabled := false
	err = a.store.update(func(state *State) error {
		pruneOAuthState(state, now)
		stored, ok := state.Codes[tokenDigest(codeValue)]
		if !ok || now.After(stored.ExpiresAt) || stored.ClientID != clientID || stored.RedirectURI != redirectURI || (resource != "" && stored.Resource != resource) || stored.Challenge != expectedChallenge {
			return nil
		}
		if _, ok := state.Clients[clientID]; !ok {
			delete(state.Codes, tokenDigest(codeValue))
			return nil
		}
		delete(state.Codes, tokenDigest(codeValue))
		token.Resource = stored.Resource
		state.Tokens[tokenDigest(plainToken)] = token
		refreshEnabled = state.Clients[clientID].RefreshEnabled
		if refreshEnabled {
			state.RefreshTokens[tokenDigest(plainRefresh)] = RefreshToken{
				ClientID: clientID, Scope: token.Scope, Resource: token.Resource,
				ExpiresAt: now.Add(refreshTokenLifetime),
			}
		}
		valid = true
		return nil
	})
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "token service is unavailable")
		return
	}
	if !valid {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code, redirect URI, resource or PKCE verifier is invalid")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	response := map[string]any{
		"access_token": plainToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenLifetime.Seconds()),
		"scope":        token.Scope,
		"resource":     token.Resource,
	}
	if refreshEnabled {
		response["refresh_token"] = plainRefresh
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostForm.Get("client_id")
	refreshValue := r.PostForm.Get("refresh_token")
	resource := r.PostForm.Get("resource")
	if clientID == "" || refreshValue == "" || (resource != "" && !a.resourceIsValid(resource)) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id and refresh_token are required; resource must match when supplied")
		return
	}
	plainToken, err := randomToken(32)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	plainRefresh, err := randomToken(32)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not rotate refresh token")
		return
	}
	now := time.Now()
	var access AccessToken
	valid := false
	err = a.store.update(func(state *State) error {
		pruneOAuthState(state, now)
		digest := tokenDigest(refreshValue)
		stored, ok := state.RefreshTokens[digest]
		client, clientOK := state.Clients[clientID]
		if !ok || !clientOK || !client.RefreshEnabled || stored.ClientID != clientID || (resource != "" && stored.Resource != resource) || now.After(stored.ExpiresAt) {
			return nil
		}
		delete(state.RefreshTokens, digest)
		access = AccessToken{ClientID: clientID, Scope: stored.Scope, Resource: stored.Resource, ExpiresAt: now.Add(accessTokenLifetime)}
		state.Tokens[tokenDigest(plainToken)] = access
		state.RefreshTokens[tokenDigest(plainRefresh)] = RefreshToken{
			ClientID: clientID, Scope: stored.Scope, Resource: stored.Resource,
			ExpiresAt: now.Add(refreshTokenLifetime),
		}
		valid = true
		return nil
	})
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "token service is unavailable")
		return
	}
	if !valid {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or issued to another client")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": plainToken, "refresh_token": plainRefresh,
		"token_type": "Bearer", "expires_in": int(accessTokenLifetime.Seconds()),
		"scope": access.Scope, "resource": access.Resource,
	})
}

func pruneOAuthState(state *State, now time.Time) {
	for digest, code := range state.Codes {
		if now.After(code.ExpiresAt) {
			delete(state.Codes, digest)
		}
	}
	for digest, token := range state.Tokens {
		if now.After(token.ExpiresAt) {
			delete(state.Tokens, digest)
		}
	}
	for digest, token := range state.RefreshTokens {
		if now.After(token.ExpiresAt) {
			delete(state.RefreshTokens, digest)
		}
	}
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && !strings.ContainsRune("-._~", ch) {
			return false
		}
	}
	return true
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "revocation request is invalid")
		return
	}
	clientID := r.PostForm.Get("client_id")
	tokenValue := r.PostForm.Get("token")
	if clientID == "" || tokenValue == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id and token are required")
		return
	}
	_ = a.store.update(func(state *State) error {
		digest := tokenDigest(tokenValue)
		if token, ok := state.Tokens[digest]; ok && token.ClientID == clientID {
			delete(state.Tokens, digest)
		}
		if token, ok := state.RefreshTokens[digest]; ok && token.ClientID == clientID {
			delete(state.RefreshTokens, digest)
		}
		return nil
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
