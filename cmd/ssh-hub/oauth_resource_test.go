package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestOptionalOAuthResource(t *testing.T) {
	for _, initial := range []string{"", "https://hub.example.test", "https://hub.example.test/mcp"} {
		t.Run(initial, func(t *testing.T) {
			a := featureApp(t)
			redirect := "http://localhost:9876/callback"
			err := a.store.update(func(s *State) error {
				s.Clients["client"] = OAuthClient{ID: "client", RedirectURIs: []string{redirect}, RefreshEnabled: true}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			verifier := strings.Repeat("a", 43)
			values := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {redirect}, "state": {"state"}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
			if initial != "" {
				values.Set("resource", initial)
			}
			_, code, ok := a.authorizeValues(values)
			if !ok || code.Resource != a.defaultResource(initial) {
				t.Fatal("authorization resource default failed")
			}
			values.Set("resource", "https://other.example/mcp")
			if _, _, ok := a.authorizeValues(values); ok {
				t.Fatal("foreign authorization resource accepted")
			}
			if err := a.store.update(func(s *State) error { s.Codes[tokenDigest("code")] = code; return nil }); err != nil {
				t.Fatal(err)
			}
			form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {"code"}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {"https://other.example/mcp"}}
			if w := formRequest(a, "/oauth/token", form); w.Code != 400 {
				t.Fatal("foreign exchange resource accepted")
			}
			form.Del("resource")
			w := formRequest(a, "/oauth/token", form)
			var tokens tokenResponse
			if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil || w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			if _, ok := a.validBearerToken("Bearer " + tokens.AccessToken); !ok {
				t.Fatal("access token invalid")
			}
			refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {tokens.RefreshToken}, "resource": {"https://other.example/mcp"}}
			if w := formRequest(a, "/oauth/token", refresh); w.Code != 400 {
				t.Fatal("foreign refresh resource accepted")
			}
			refresh.Del("resource")
			w = formRequest(a, "/oauth/token", refresh)
			var result map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &result)
			if w.Code != 200 || result["resource"] != code.Resource {
				t.Fatal(w.Body.String())
			}
			if _, ok := a.validBearerToken("Bearer " + result["access_token"].(string)); !ok {
				t.Fatal("refreshed token invalid")
			}
		})
	}
}
