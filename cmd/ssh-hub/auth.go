package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"time"
)

type loginPageData struct {
	Setup       bool
	SetupToken  string
	Next        string
	Error       string
	OIDCEnabled bool
	OIDCLabel   string
}

func (a *App) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.currentSession(r); ok {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	var passwordHash string
	_ = a.store.view(func(state State) error { passwordHash = state.PasswordHash; return nil })
	data := loginPageData{
		Setup:       passwordHash == "",
		SetupToken:  a.setupToken(),
		Next:        safeNext(r.URL.Query().Get("next")),
		OIDCEnabled: a.oidc != nil,
		OIDCLabel:   a.oidcLabel(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = a.index.ExecuteTemplate(w, "login.html", data)
}

func (a *App) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		a.renderLogin(w, loginPageData{Error: "请求内容无效。", Next: "/ui"}, http.StatusBadRequest)
		return
	}
	var passwordHash string
	_ = a.store.view(func(state State) error { passwordHash = state.PasswordHash; return nil })
	if passwordHash == "" {
		token := a.setupToken()
		if token == "" || subtle.ConstantTimeCompare([]byte(r.FormValue("setup_token")), []byte(token)) != 1 {
			a.renderLogin(w, loginPageData{Setup: true, SetupToken: token, Next: safeNext(r.FormValue("next")), Error: "初始化口令不正确。"}, http.StatusUnauthorized)
			return
		}
		password := r.FormValue("password")
		if password != r.FormValue("password_confirm") {
			a.renderLogin(w, loginPageData{Setup: true, SetupToken: token, Next: safeNext(r.FormValue("next")), Error: "两次输入的密码不一致。"}, http.StatusBadRequest)
			return
		}
		if err := a.setInitialPassword(password); err != nil {
			a.renderLogin(w, loginPageData{Setup: true, SetupToken: token, Next: safeNext(r.FormValue("next")), Error: err.Error()}, http.StatusBadRequest)
			return
		}
		a.finishLogin(w, r, safeNext(r.FormValue("next")))
		return
	}

	remote := clientIP(r.RemoteAddr)
	if !a.loginAllowed(remote) {
		a.renderLogin(w, loginPageData{Next: safeNext(r.FormValue("next")), Error: "登录尝试过多，请稍后再试。"}, http.StatusTooManyRequests)
		return
	}
	if !verifyPassword(r.FormValue("password"), passwordHash) {
		a.recordLoginFailure(remote)
		a.renderLogin(w, loginPageData{Next: safeNext(r.FormValue("next")), Error: "账号或密码不正确。"}, http.StatusUnauthorized)
		return
	}
	a.clearLoginFailures(remote)
	a.finishLogin(w, r, safeNext(r.FormValue("next")))
}

func (a *App) finishLogin(w http.ResponseWriter, r *http.Request, next string) {
	if _, err := a.createSession(w); err != nil {
		a.renderLogin(w, loginPageData{Next: next, Error: "无法创建登录会话。"}, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) renderLogin(w http.ResponseWriter, data loginPageData, status int) {
	var passwordHash string
	_ = a.store.view(func(state State) error { passwordHash = state.PasswordHash; return nil })
	data.Setup = passwordHash == ""
	if data.Setup {
		data.SetupToken = a.setupToken()
	}
	if data.Next == "" {
		data.Next = "/ui"
	}
	data.OIDCEnabled = a.oidc != nil
	data.OIDCLabel = a.oidcLabel()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = a.index.ExecuteTemplate(w, "login.html", data)
}

func (a *App) loginAllowed(ip string) bool {
	now := time.Now()
	a.attemptsMu.Lock()
	defer a.attemptsMu.Unlock()
	entry, ok := a.attempts[ip]
	if !ok {
		return true
	}
	if now.Before(entry.BlockedTo) {
		return false
	}
	if now.After(entry.WindowEnds) {
		delete(a.attempts, ip)
	}
	return true
}

func (a *App) recordLoginFailure(ip string) {
	now := time.Now()
	a.attemptsMu.Lock()
	defer a.attemptsMu.Unlock()
	entry := a.attempts[ip]
	if now.After(entry.WindowEnds) {
		entry = loginAttempt{WindowEnds: now.Add(15 * time.Minute)}
	}
	entry.Count++
	if entry.Count >= 8 {
		entry.BlockedTo = now.Add(15 * time.Minute)
	}
	a.attempts[ip] = entry
}

func (a *App) clearLoginFailures(ip string) {
	a.attemptsMu.Lock()
	delete(a.attempts, ip)
	a.attemptsMu.Unlock()
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	if key, _, ok := a.currentSession(r); ok {
		a.sessionsMu.Lock()
		delete(a.sessions, key)
		a.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: "ssh_hub_session", Value: "", Path: "/", HttpOnly: true,
		Secure: a.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
