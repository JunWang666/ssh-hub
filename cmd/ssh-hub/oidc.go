package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcCallbackPath = "/auth/oidc/callback"
	oidcStateCookie  = "ssh_hub_oidc_state"
	oidcLoginTTL     = 10 * time.Minute
	maxOIDCLogins    = 1024
)

type oidcSettings struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	AllowedEmails   string
	AllowedSubjects string
	Label           string
}

type oidcProvider struct {
	issuer        string
	label         string
	httpClient    *http.Client
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	allowedEmails map[string]struct{}
	allowedSubs   map[string]struct{}
}

type oidcLoginState struct {
	Nonce     string
	Verifier  string
	Next      string
	ExpiresAt time.Time
}

type oidcClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func oidcSettingsFromEnv() oidcSettings {
	return oidcSettings{
		Issuer:          os.Getenv("SSHHUB_OIDC_ISSUER"),
		ClientID:        os.Getenv("SSHHUB_OIDC_CLIENT_ID"),
		ClientSecret:    os.Getenv("SSHHUB_OIDC_CLIENT_SECRET"),
		AllowedEmails:   os.Getenv("SSHHUB_OIDC_ALLOWED_EMAILS"),
		AllowedSubjects: os.Getenv("SSHHUB_OIDC_ALLOWED_SUBJECTS"),
		Label:           os.Getenv("SSHHUB_OIDC_LABEL"),
	}
}

func (a *App) configureOIDC(settings oidcSettings) error {
	return a.configureOIDCWithHTTPClient(settings, &http.Client{Timeout: 15 * time.Second})
}

func (a *App) configureOIDCWithHTTPClient(settings oidcSettings, client *http.Client) error {
	if strings.TrimSpace(settings.Issuer) == "" && strings.TrimSpace(settings.ClientID) == "" &&
		strings.TrimSpace(settings.ClientSecret) == "" && strings.TrimSpace(settings.AllowedEmails) == "" &&
		strings.TrimSpace(settings.AllowedSubjects) == "" && strings.TrimSpace(settings.Label) == "" {
		return nil
	}
	if strings.TrimSpace(settings.Issuer) == "" || strings.TrimSpace(settings.ClientID) == "" || strings.TrimSpace(settings.ClientSecret) == "" {
		return errors.New("SSHHUB_OIDC_ISSUER, SSHHUB_OIDC_CLIENT_ID, and SSHHUB_OIDC_CLIENT_SECRET must all be set")
	}
	if err := validateOIDCIssuer(settings.Issuer); err != nil {
		return err
	}

	allowedEmails := parseOIDCAllowlist(settings.AllowedEmails, true)
	allowedSubjects := parseOIDCAllowlist(settings.AllowedSubjects, false)
	if len(allowedEmails) == 0 && len(allowedSubjects) == 0 {
		return errors.New("configure at least one SSHHUB_OIDC_ALLOWED_EMAILS or SSHHUB_OIDC_ALLOWED_SUBJECTS entry")
	}

	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), client), 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, settings.Issuer)
	if err != nil {
		return errors.New("discover OIDC provider: " + err.Error())
	}
	label := strings.TrimSpace(settings.Label)
	if label == "" {
		label = "使用第三方账号登录"
	}
	a.oidc = &oidcProvider{
		issuer:     settings.Issuer,
		label:      label,
		httpClient: client,
		oauth: oauth2.Config{
			ClientID:     settings.ClientID,
			ClientSecret: settings.ClientSecret,
			RedirectURL:  a.publicURL + oidcCallbackPath,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: settings.ClientID}),
		allowedEmails: allowedEmails,
		allowedSubs:   allowedSubjects,
	}
	return nil
}

func validateOIDCIssuer(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("SSHHUB_OIDC_ISSUER must be an issuer URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return errors.New("SSHHUB_OIDC_ISSUER must use HTTPS; HTTP is allowed only for localhost")
	}
	return nil
}

func parseOIDCAllowlist(value string, foldCase bool) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if foldCase {
			entry = strings.ToLower(entry)
		}
		if entry != "" {
			allowed[entry] = struct{}{}
		}
	}
	return allowed
}

func oidcIdentityAllowed(claims oidcClaims, allowedEmails, allowedSubjects map[string]struct{}) bool {
	if claims.Subject != "" {
		if _, ok := allowedSubjects[claims.Subject]; ok {
			return true
		}
	}
	if claims.EmailVerified && claims.Email != "" {
		_, ok := allowedEmails[strings.ToLower(strings.TrimSpace(claims.Email))]
		return ok
	}
	return false
}

func (a *App) oidcLabel() string {
	if a.oidc == nil {
		return ""
	}
	return a.oidc.label
}

func (a *App) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	provider := a.oidc
	if provider == nil {
		http.NotFound(w, r)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	if _, _, ok := a.currentSession(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "无法启动第三方登录。", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "无法启动第三方登录。", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	now := time.Now()
	a.oidcMu.Lock()
	for oldState, pending := range a.oidcLogins {
		if now.After(pending.ExpiresAt) {
			delete(a.oidcLogins, oldState)
		}
	}
	if len(a.oidcLogins) >= maxOIDCLogins {
		a.oidcMu.Unlock()
		http.Error(w, "登录请求过多，请稍后重试。", http.StatusTooManyRequests)
		return
	}
	a.oidcLogins[state] = oidcLoginState{Nonce: nonce, Verifier: verifier, Next: next, ExpiresAt: now.Add(oidcLoginTTL)}
	a.oidcMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: oidcCallbackPath,
		HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(oidcLoginTTL.Seconds()),
	})
	authURL := provider.oauth.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oidc.Nonce(nonce),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider := a.oidc
	if provider == nil {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	decodedState, decodeErr := base64.RawURLEncoding.DecodeString(state)
	if decodeErr != nil || len(decodedState) != 32 {
		clearOIDCStateCookie(w, a)
		a.renderLogin(w, loginPageData{Error: "第三方登录状态无效，请重试。"}, http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		clearOIDCStateCookie(w, a)
		a.renderLogin(w, loginPageData{Error: "第三方登录状态无效，请重试。"}, http.StatusUnauthorized)
		return
	}
	clearOIDCStateCookie(w, a)
	a.oidcMu.Lock()
	pending, ok := a.oidcLogins[state]
	delete(a.oidcLogins, state)
	a.oidcMu.Unlock()
	if !ok || time.Now().After(pending.ExpiresAt) {
		a.renderLogin(w, loginPageData{Error: "第三方登录请求已过期，请重试。"}, http.StatusUnauthorized)
		return
	}
	if responseIssuer := r.URL.Query().Get("iss"); responseIssuer != "" && responseIssuer != provider.issuer {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "第三方身份提供方不匹配。"}, http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("error") != "" {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "第三方登录未完成，请重试。"}, http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "第三方登录响应无效，请重试。"}, http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), provider.httpClient), 15*time.Second)
	defer cancel()
	token, err := provider.oauth.Exchange(ctx, code, oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "无法验证第三方登录，请重试。"}, http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "第三方身份提供方未返回身份令牌。"}, http.StatusUnauthorized)
		return
	}
	idToken, err := provider.verifier.Verify(ctx, rawIDToken)
	if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(pending.Nonce)) != 1 {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "第三方身份令牌无效，请重试。"}, http.StatusUnauthorized)
		return
	}
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.Subject != idToken.Subject {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "无法读取第三方账号信息。"}, http.StatusUnauthorized)
		return
	}
	if !oidcIdentityAllowed(claims, provider.allowedEmails, provider.allowedSubs) {
		a.renderLogin(w, loginPageData{Next: pending.Next, Error: "此第三方账号未获 SSH Hub 管理权限。"}, http.StatusForbidden)
		return
	}
	a.finishLogin(w, r, pending.Next)
}

func clearOIDCStateCookie(w http.ResponseWriter, a *App) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: "", Path: oidcCallbackPath, HttpOnly: true,
		Secure: a.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
