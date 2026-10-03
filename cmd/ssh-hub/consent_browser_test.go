package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
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
	server := httptest.NewUnstartedServer(app.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	app.publicURL = "http://" + server.Listener.Addr().String()
	client.RedirectURIs = []string{app.publicURL + "/callback"}
	code = AuthCode{ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Scope: "mcp", Resource: app.publicURL + "/mcp"}
	if err := store.update(func(state *State) error { state.Clients[client.ID] = client; return nil }); err != nil {
		t.Fatal(err)
	}
	server.Start()
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

func TestBrowserAdminWorkflow(t *testing.T) {
	browser := os.Getenv("SSHHUB_TEST_CHROMIUM")
	if browser == "" {
		t.Skip("set SSHHUB_TEST_CHROMIUM")
	}
	a := featureApp(t)
	a.adminURL = ""
	host, _, _ := setupExecution(t, a, true)
	routes := a.routes()
	results := make(chan string, 1)
	script := `<script>
window.confirm=()=>true;
(async()=>{
const pause=()=>new Promise(r=>setTimeout(r,50));
async function waitFor(fn){for(let n=0;n<100;n++){if(fn())return;await pause()}throw new Error('UI wait timed out')}
await load();
if(document.getElementById('key-dialog').open)throw new Error('form should start collapsed');
document.getElementById('add-key').click();
document.getElementById('key-name').value='browser-generated';
document.getElementById('key-form').requestSubmit();
await waitFor(()=>!document.getElementById('key-install').hidden);
if(!document.getElementById('install-command').value.includes('/install/'))throw new Error('missing install command');
closeDialog('install-dialog');
document.getElementById('add-host').click();
document.getElementById('host-name').value='browser-host';
document.getElementById('host-address').value=ADDRESS;
document.getElementById('host-user').value='tester';
document.getElementById('probe-host').click();
await waitFor(()=>document.getElementById('host-fingerprint').value.startsWith('SHA256:'));
document.getElementById('host-key').selectedIndex=1;
document.getElementById('host-form').requestSubmit();
await waitFor(()=>document.getElementById('hosts-list').textContent.includes('browser-host'));
await loadAudit();
showPage('clients');showClientPolicy('c1');
if(!document.getElementById('policy-dialog').open)throw new Error('missing policy dialog');
closeDialog('policy-dialog');showPage('hosts');
const checkButton=document.createElement('button');await checkHost('h1',checkButton);
if(!document.getElementById('hosts-list').textContent.includes('在线'))throw new Error('missing live health status');
await fetch('/test-result',{method:'POST',body:'ok'});
})().catch(async e=>{await fetch('/test-result',{method:'POST',body:String(e)})});
</script>`
	address, _ := json.Marshal(host.Address)
	script = strings.Replace(script, "ADDRESS", string(address), 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			_, _ = a.createSession(w)
			http.Redirect(w, r, "/ui", 303)
		case "/test-result":
			body, _ := io.ReadAll(r.Body)
			results <- string(body)
			w.WriteHeader(204)
		case "/ui":
			recorder := httptest.NewRecorder()
			routes.ServeHTTP(recorder, r)
			for k, v := range recorder.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			_, _ = io.WriteString(w, script)
		default:
			routes.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	a.publicURL = "http://" + server.Listener.Addr().String()
	server.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser, "--headless", "--no-sandbox", "--disable-gpu", "--no-proxy-server", "--user-data-dir="+t.TempDir(), "--virtual-time-budget=12000", "--dump-dom", server.URL+"/start")
	if screenshot := os.Getenv("SSHHUB_TEST_SCREENSHOT"); screenshot != "" {
		cmd.Args = append(cmd.Args, "--window-size=1400,1000", "--screenshot="+screenshot)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v %s", err, output)
	}
	select {
	case result := <-results:
		if result != "ok" {
			t.Fatal(result)
		}
	default:
		t.Fatalf("browser workflow did not finish: %s", output)
	}
}
