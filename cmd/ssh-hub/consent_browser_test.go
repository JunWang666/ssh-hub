package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Opt in with SSHHUB_TEST_CHROMIUM=/path/to/chromium. This uses a native
// form submission because fetch does not reproduce no-referrer's null Origin.
func TestBrowserConsentSubmission(t *testing.T) {
	browser := os.Getenv("SSHHUB_TEST_CHROMIUM")
	if browser == "" {
		t.Skip("set SSHHUB_TEST_CHROMIUM to run the native browser regression")
	}
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(store, "http://localhost")
	client := OAuthClient{ID: "browser-test", Name: "Browser test"}
	var code AuthCode
	type result struct {
		origin, location string
		status           int
	}
	results := make(chan result, 1)
	routes := app.routes()
	server := httptest.NewServer(app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			session, err := app.createSession(w)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			app.renderConsent(w, client, code, "browser-state", session.CSRF)
			_, _ = io.WriteString(w, `<script>document.forms[0].requestSubmit(document.querySelector('.approve'))</script>`)
		case "/oauth/authorize":
			recorder := httptest.NewRecorder()
			routes.ServeHTTP(recorder, r)
			results <- result{r.Header.Get("Origin"), recorder.Header().Get("Location"), recorder.Code}
			for key, values := range recorder.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		case "/callback":
			_, _ = io.WriteString(w, "authorized")
		default:
			http.NotFound(w, r)
		}
	})))
	defer server.Close()
	app.publicURL = server.URL
	client.RedirectURIs = []string{server.URL + "/callback"}
	code = AuthCode{ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Scope: "mcp", Resource: server.URL + "/mcp"}
	if err := store.update(func(state *State) error { state.Clients[client.ID] = client; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser, "--headless", "--no-sandbox", "--disable-gpu", "--no-proxy-server", "--user-data-dir="+t.TempDir(), "--dump-dom", server.URL+"/start")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	select {
	case got := <-results:
		callback, err := url.Parse(got.location)
		if got.status != http.StatusSeeOther || got.origin != server.URL || err != nil || callback.Query().Get("code") == "" || callback.Query().Get("state") != "browser-state" {
			t.Fatalf("consent POST: status=%d origin=%q callback_valid=%t", got.status, got.origin, err == nil && callback.Query().Get("code") != "")
		}
		t.Logf("native consent POST: Origin=%s, status=%d, authorization code issued", got.origin, got.status)
	default:
		t.Fatal("browser did not submit the consent form")
	}
}
