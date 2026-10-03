package main

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

type DeviceGrant struct {
	ClientID  string    `json:"client_id"`
	UserCode  string    `json:"user_code"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
	LastPoll  time.Time `json:"last_poll"`
	Interval  int       `json:"interval"`
}

func normalizeUserCode(code string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(code)), "-", "")
}

func (a *App) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if !a.allowClientRegistration("device:" + clientIP(r.RemoteAddr)) {
		oauthError(w, 429, "slow_down", "too many device requests")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil || !a.resourceIsValid(a.defaultResource(r.PostForm.Get("resource"))) || (r.PostForm.Get("scope") != "" && r.PostForm.Get("scope") != "mcp") {
		oauthError(w, 400, "invalid_request", "invalid resource or scope; only mcp scope is supported")
		return
	}
	plain, err := randomToken(32)
	if err != nil {
		oauthError(w, 500, "server_error", "cannot create device code")
		return
	}
	var raw [5]byte
	if _, err := rand.Read(raw[:]); err != nil {
		oauthError(w, 500, "server_error", "cannot create user code")
		return
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	grant := DeviceGrant{ClientID: r.PostForm.Get("client_id"), UserCode: code, Resource: a.defaultResource(r.PostForm.Get("resource")), ExpiresAt: time.Now().Add(10 * time.Minute), Status: "pending", Interval: 5}
	err = a.store.update(func(state *State) error {
		client, ok := state.Clients[grant.ClientID]
		if !ok || !client.DeviceEnabled {
			return errors.New("client does not support device authorization")
		}
		for digest, stored := range state.DeviceGrants {
			if time.Now().After(stored.ExpiresAt) {
				delete(state.DeviceGrants, digest)
			} else if stored.UserCode == code {
				return errors.New("retry device authorization")
			}
		}
		if len(state.DeviceGrants) >= 2000 {
			return errors.New("too many pending device grants")
		}
		state.DeviceGrants[tokenDigest(plain)] = grant
		return nil
	})
	if err != nil {
		oauthError(w, 400, "invalid_client", err.Error())
		return
	}
	code = code[:4] + "-" + code[4:]
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"device_code": plain, "user_code": code, "verification_uri": a.publicURL + "/oauth/device/verify", "verification_uri_complete": a.publicURL + "/oauth/device/verify?user_code=" + url.QueryEscape(code), "expires_in": 600, "interval": 5})
}

func (a *App) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if r.PostForm.Get("device_code") == "" || r.PostForm.Get("client_id") == "" {
		oauthError(w, 400, "invalid_request", "device_code and client_id required")
		return
	}
	access, err := randomToken(32)
	if err != nil {
		oauthError(w, 500, "server_error", "token generation failed")
		return
	}
	refresh, err := randomToken(32)
	if err != nil {
		oauthError(w, 500, "server_error", "token generation failed")
		return
	}
	code, description, resource, refreshEnabled := "invalid_grant", "device code is invalid", "", false
	now := time.Now()
	err = a.store.update(func(state *State) error {
		digest := tokenDigest(r.PostForm.Get("device_code"))
		grant, ok := state.DeviceGrants[digest]
		client, exists := state.Clients[r.PostForm.Get("client_id")]
		if !ok || !exists || !client.DeviceEnabled || grant.ClientID != client.ID {
			return nil
		}
		if r.PostForm.Get("resource") != "" && r.PostForm.Get("resource") != grant.Resource {
			code, description = "invalid_target", "resource does not match"
			return nil
		}
		if now.After(grant.ExpiresAt) {
			delete(state.DeviceGrants, digest)
			code, description = "expired_token", "device code expired"
			return nil
		}
		if !grant.LastPoll.IsZero() && now.Sub(grant.LastPoll) < time.Duration(grant.Interval)*time.Second {
			grant.Interval += 5
			grant.LastPoll = now
			state.DeviceGrants[digest] = grant
			code, description = "slow_down", "increase polling interval by five seconds"
			return nil
		}
		grant.LastPoll = now
		state.DeviceGrants[digest] = grant
		switch grant.Status {
		case "pending":
			code, description = "authorization_pending", "waiting for browser approval"
		case "denied":
			delete(state.DeviceGrants, digest)
			code, description = "access_denied", "user denied authorization"
		case "approved":
			delete(state.DeviceGrants, digest)
			resource, refreshEnabled = grant.Resource, client.RefreshEnabled
			state.Tokens[tokenDigest(access)] = AccessToken{ClientID: client.ID, Scope: "mcp", Resource: resource, ExpiresAt: now.Add(accessTokenLifetime)}
			if refreshEnabled {
				state.RefreshTokens[tokenDigest(refresh)] = RefreshToken{ClientID: client.ID, Scope: "mcp", Resource: resource, ExpiresAt: now.Add(refreshTokenLifetime)}
			}
			code = ""
		}
		return nil
	})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable", "token service unavailable")
		return
	}
	if code != "" {
		oauthError(w, 400, code, description)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(accessTokenLifetime.Seconds()), "scope": "mcp", "resource": resource}
	if refreshEnabled {
		result["refresh_token"] = refresh
	}
	writeJSON(w, 200, result)
}

var devicePage = template.Must(template.New("device").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SSH Hub 设备登录</title><style>body{font:16px system-ui;max-width:620px;margin:60px auto;padding:24px;background:#f4f6fa;color:#182235}input,button{padding:12px;margin:8px}code{font-size:24px}small{overflow-wrap:anywhere}</style><h1>远程设备登录</h1>{{if .Message}}<p>{{.Message}}</p>{{else}}<p>请核对远程终端显示的设备码，只批准你正在登录的设备。</p><form method="get"><input name="user_code" value="{{.Code}}" placeholder="XXXX-XXXX" required><button>查找设备</button></form>{{if .Client}}<p>客户端：<strong>{{.Client}}</strong></p><small>{{.ClientID}}</small><p>设备码：<code>{{.Code}}</code></p><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="user_code" value="{{.Code}}"><button name="decision" value="approve">确认登录此设备</button><button name="decision" value="deny">拒绝</button></form><p>机器权限和执行审批在管理控制台按客户端配置。</p>{{end}}{{end}}</html>`))

func (a *App) renderDevice(w http.ResponseWriter, status int, data map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = devicePage.Execute(w, data)
}

func (a *App) handleDeviceVerifyGet(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	code := normalizeUserCode(r.URL.Query().Get("user_code"))
	data := map[string]string{"Code": code, "CSRF": session.CSRF}
	if code != "" {
		if !a.loginAllowed("device-verify:" + session.Actor) {
			a.renderDevice(w, 429, map[string]string{"Message": "尝试过多，请稍后重试。"})
			return
		}
		_ = a.store.view(func(state State) error {
			for _, grant := range state.DeviceGrants {
				if grant.UserCode == code && grant.Status == "pending" && time.Now().Before(grant.ExpiresAt) {
					if client, ok := state.Clients[grant.ClientID]; ok {
						data["Client"], data["ClientID"] = client.Name, client.ID
					}
				}
			}
			return nil
		})
		if data["Client"] == "" {
			a.recordLoginFailure("device-verify:" + session.Actor)
			data["Message"] = "设备码无效、已使用或已过期，请从终端重新登录。"
		}
	}
	a.renderDevice(w, 200, data)
}

func (a *App) handleDeviceVerifyPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	session, ok := a.checkCSRF(w, r)
	if !ok {
		return
	}
	if !a.loginAllowed("device-verify:" + session.Actor) {
		a.renderDevice(w, 429, map[string]string{"Message": "尝试过多，请稍后重试。"})
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "deny" {
		http.Error(w, "invalid decision", 400)
		return
	}
	found := false
	err := a.store.update(func(state *State) error {
		for digest, grant := range state.DeviceGrants {
			if grant.UserCode == normalizeUserCode(r.PostForm.Get("user_code")) && grant.Status == "pending" && time.Now().Before(grant.ExpiresAt) {
				if _, ok := state.Clients[grant.ClientID]; !ok {
					return nil
				}
				grant.Status = "denied"
				if decision == "approve" {
					grant.Status = "approved"
				}
				state.DeviceGrants[digest] = grant
				found = true
				break
			}
		}
		return nil
	})
	if err != nil {
		a.renderDevice(w, 500, map[string]string{"Message": "无法保存授权，请重试。"})
		return
	}
	if !found {
		a.recordLoginFailure("device-verify:" + session.Actor)
		a.renderDevice(w, 400, map[string]string{"Message": "设备码无效、已处理或已过期。"})
		return
	}
	a.clearLoginFailures("device-verify:" + session.Actor)
	message := "已拒绝设备登录。"
	if decision == "approve" {
		message = "设备已授权，可以关闭此页面返回远程终端，无需复制回调地址。请在管理控制台为新客户端配置机器权限。"
	}
	a.renderDevice(w, 200, map[string]string{"Message": message})
}
