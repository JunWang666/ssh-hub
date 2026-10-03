package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidSameOriginNormalizesAuthority(t *testing.T) {
	app := &App{publicURL: "https://sshhub.example.test", adminURL: "https://sshadmin.example.test"}
	tests := []struct {
		name        string
		origin      string
		requestHost string
		want        bool
	}{
		{name: "public origin with explicit default port", origin: "https://sshhub.example.test:443", requestHost: "sshhub.example.test", want: true},
		{name: "case-insensitive public host", origin: "https://SSHHUB.EXAMPLE.TEST", requestHost: "sshhub.example.test:443", want: true},
		{name: "separate admin origin", origin: "https://sshadmin.example.test", requestHost: "SSHADMIN.example.test:443", want: true},
		{name: "untrusted origin", origin: "https://chatgpt.com", requestHost: "sshhub.example.test", want: false},
		{name: "opaque origin remains rejected", origin: "null", requestHost: "sshhub.example.test", want: false},
		{name: "different configured host", origin: "https://sshhub.example.test", requestHost: "sshadmin.example.test", want: false},
		{name: "non-default port", origin: "https://sshhub.example.test:444", requestHost: "sshhub.example.test", want: false},
		{name: "origin path", origin: "https://sshhub.example.test/path", requestHost: "sshhub.example.test", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := app.validSameOrigin(tt.origin, tt.requestHost); got != tt.want {
				t.Fatalf("validSameOrigin(%q, %q) = %t, want %t", tt.origin, tt.requestHost, got, tt.want)
			}
		})
	}
}

func TestAuthorizeConsentCSRFAcceptsEquivalentOrigin(t *testing.T) {
	app := &App{
		publicURL: "https://sshhub.example.test",
		adminURL:  "https://sshadmin.example.test",
		sessions: map[string]Session{
			"session-key": {CSRF: "csrf-token", ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	request := httptest.NewRequest(http.MethodPost, "https://sshhub.example.test/oauth/authorize", nil)
	request.Host = "SSHHUB.example.test:443"
	request.AddCookie(&http.Cookie{Name: "ssh_hub_session", Value: "session-key"})
	request.Header.Set("X-CSRF-Token", "csrf-token")
	request.Header.Set("Origin", "https://sshhub.example.test")
	response := httptest.NewRecorder()

	if _, ok := app.checkCSRF(response, request); !ok {
		t.Fatalf("checkCSRF rejected equivalent origin: status %d, body %q", response.Code, response.Body.String())
	}
}
