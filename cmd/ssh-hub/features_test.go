package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func featureApp(t *testing.T) *App {
	t.Helper()
	store, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := newApp(store, "https://hub.example.test")
	app.adminURL = "https://admin.example.test"
	app.keysDir = t.TempDir()
	return app
}

func adminRequest(t *testing.T, a *App, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	cookie := httptest.NewRecorder()
	session, err := a.createSession(cookie)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, a.adminURL+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", a.adminURL)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	r.AddCookie(cookie.Result().Cookies()[0])
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}

func TestGeneratedMountedKeysAndPublicInstaller(t *testing.T) {
	a := featureApp(t)
	key, err := a.createKey(createKeyRequest{Name: "generated", Source: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(a.generatedKeysDir(), key.Path))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v %v", info, err)
	}
	data, err := readKeyFile(a.generatedKeysDir(), key.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.keysDir, "mounted"), data, 0600); err != nil {
		t.Fatal(err)
	}
	mounted, err := a.createKey(createKeyRequest{Name: "mounted", Source: "mounted", Path: "mounted"})
	if err != nil {
		t.Fatal(err)
	}
	if mounted.PublicKey != key.PublicKey {
		t.Fatal("mounted key differs")
	}
	secret, err := a.store.decryptSecret(mounted.Secret)
	if err != nil || strings.Contains(string(secret), "PRIVATE KEY") {
		t.Fatal("mounted private key copied to store")
	}
	if _, err := a.createKey(createKeyRequest{Name: "escape", Source: "mounted", Path: "../master.key"}); err == nil {
		t.Fatal("path escape accepted")
	}
	if err := os.Symlink(filepath.Join(a.generatedKeysDir(), key.Path), filepath.Join(a.keysDir, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.createKey(createKeyRequest{Name: "symlink", Source: "mounted", Path: "escape"}); err == nil {
		t.Fatal("symlink escape accepted")
	}
	for _, route := range []string{"/install/", "/public-keys/"} {
		r := httptest.NewRequest("GET", a.publicURL+route+key.InstallToken, nil)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE KEY") || !strings.Contains(w.Body.String(), key.PublicKey) {
			t.Fatalf("public route %s failed", route)
		}
	}
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(authFile, []byte("# existing entry without newline"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		cmd := exec.Command("sh")
		cmd.Env = append(os.Environ(), "HOME="+home)
		cmd.Stdin = strings.NewReader(installScript(key.PublicKey))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("installer: %v %s", err, output)
		}
	}
	installed, _ := os.ReadFile(authFile)
	if strings.Count(string(installed), key.PublicKey) != 1 || !strings.HasPrefix(string(installed), "# existing entry without newline\n") {
		t.Fatal("installer duplicated key or replaced existing keys")
	}
	// Preserve existing restrictions rather than adding an unrestricted duplicate.
	restricted := "restrict " + key.PublicKey + " comment\n"
	_ = os.WriteFile(authFile, []byte(restricted), 0600)
	cmd := exec.Command("sh")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader(installScript(key.PublicKey))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installer: %v %s", err, output)
	}
	installed, _ = os.ReadFile(authFile)
	if string(installed) != restricted {
		t.Fatal("installer bypassed existing authorized_keys restrictions")
	}
	w := adminRequest(t, a, "DELETE", "/api/keys/"+key.ID, "")
	if w.Code != 204 {
		t.Fatal(w.Body.String())
	}
	if a.publishedKey(key.InstallToken) != "" {
		t.Fatal("deleted key still published")
	}
	if _, err := os.Stat(filepath.Join(a.generatedKeysDir(), key.Path)); !os.IsNotExist(err) {
		t.Fatal("deleted generated private key remains")
	}
	w = adminRequest(t, a, "DELETE", "/api/keys/"+mounted.ID, "")
	if w.Code != 204 {
		t.Fatal(w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(a.keysDir, "mounted")); err != nil {
		t.Fatal("mounted file was removed")
	}
}

func sshFixture(t *testing.T, acceptedKey string) (string, string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(private)
	connections, auths := &atomic.Int32{}, &atomic.Int32{}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		auths.Add(1)
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != acceptedKey {
			return nil, io.EOF
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.Close()
				server, chans, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range chans {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						var command struct{ Command string }
						_ = ssh.Unmarshal(request.Payload, &command)
						_ = request.Reply(true, nil)
						_, _ = channel.Write([]byte("ran: " + command.Command + "\n"))
						_, _ = channel.Stderr().Write([]byte("test stderr\n"))
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
						_ = channel.Close()
						break
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(hostSigner.PublicKey()), connections, auths
}

func setupExecution(t *testing.T, a *App, approval bool) (Host, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, err := a.createKey(createKeyRequest{Name: "exec", Source: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	address, fingerprint, connections, auths := sshFixture(t, key.PublicKey)
	host := Host{ID: "h1", Name: "test host", Address: address, Username: "tester", KeyID: key.ID, HostKeyFingerprint: fingerprint, TimeoutSeconds: 5}
	if err := a.store.update(func(state *State) error {
		state.Hosts[host.ID] = host
		state.Clients["c1"] = OAuthClient{ID: "c1", Name: "client one", HostAccessConfigured: true, AllowedHostIDs: []string{host.ID}, RequireApproval: approval}
		state.Clients["c2"] = OAuthClient{ID: "c2", Name: "other client", HostAccessConfigured: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return host, connections, auths
}

func TestClientIsolationApprovalAndAudit(t *testing.T) {
	a := featureApp(t)
	host, connections, _ := setupExecution(t, a, true)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "c1")
	record, err := a.submitExecution(ctx, host.ID, "uname -a", 3)
	if err != nil || record.Status != "pending" {
		t.Fatalf("submit: %v %+v", err, record)
	}
	if connections.Load() != 0 {
		t.Fatal("SSH connection made before approval")
	}
	other := context.WithValue(context.Background(), clientContextKey{}, "c2")
	if _, err := a.clientAudit(other, record.ID); err == nil {
		t.Fatal("other client accessed audit")
	}
	denied, err := a.submitExecution(other, host.ID, "id", 3)
	if err != nil || denied.Status != "denied" || connections.Load() != 0 {
		t.Fatal("unauthorized execution was not denied")
	}
	listed, rpcErr := a.callTool(json.RawMessage(`{"name":"ssh_list_hosts","arguments":{}}`), other)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	listedJSON, _ := json.Marshal(listed)
	if strings.Contains(string(listedJSON), host.Address) {
		t.Fatal("host leaked through list")
	}
	approved, err := a.decideAudit(record.ID, "approve", "local-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.decideAudit(record.ID, "approve", "local-admin"); err == nil {
		t.Fatal("duplicate approval accepted")
	}
	finished := a.executeAudited(ctx, approved)
	if finished.ExitCode != 7 || finished.Status != "failed" || !strings.Contains(finished.Stdout, "uname -a") || !strings.Contains(finished.Stderr, "test stderr") {
		t.Fatalf("execution audit: %+v", finished)
	}
	if connections.Load() != 1 {
		t.Fatal("unexpected connection count")
	}
	reloaded, err := a.clientAudit(ctx, record.ID)
	if err != nil || reloaded.Stdout != finished.Stdout || reloaded.DecidedBy != "local-admin" {
		t.Fatal("audit not persisted")
	}
	if err := a.recoverAuditSessions(); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := a.clientAudit(ctx, record.ID)
	if unchanged.Status != "failed" {
		t.Fatal("completed audit changed during recovery")
	}
	pending, _ := a.submitExecution(ctx, host.ID, "id", 3)
	_ = a.store.update(func(state *State) error {
		c := state.Clients["c1"]
		c.AllowedHostIDs = nil
		state.Clients["c1"] = c
		return nil
	})
	revoked, err := a.decideAudit(pending.ID, "approve", "local-admin")
	if err != nil || revoked.Status != "denied" || connections.Load() != 1 {
		t.Fatal("approval ignored revoked permissions")
	}
}

func TestAuditFailureAndProbeNeverAuthenticate(t *testing.T) {
	a := featureApp(t)
	host, connections, auths := setupExecution(t, a, false)
	fingerprint, _, err := probeHost(context.Background(), host.Address)
	if err != nil || fingerprint != host.HostKeyFingerprint || auths.Load() != 0 {
		t.Fatalf("probe authenticated or wrong fingerprint: %v", err)
	}
	if err := os.WriteFile(a.auditDir(), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = a.submitExecution(context.WithValue(context.Background(), clientContextKey{}, "c1"), host.ID, "id", 3)
	if err == nil || connections.Load() != 1 {
		t.Fatal("execution continued without audit storage")
	}
}

func TestMountedKeyRotationRejected(t *testing.T) {
	a := featureApp(t)
	write := func() {
		_, private, _ := ed25519.GenerateKey(rand.Reader)
		block, _ := ssh.MarshalPrivateKey(private, "")
		if err := os.WriteFile(filepath.Join(a.keysDir, "key"), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	key, err := a.createKey(createKeyRequest{Name: "mounted", Source: "mounted", Path: "key"})
	if err != nil {
		t.Fatal(err)
	}
	write()
	if _, err := a.keySigner(key); err == nil {
		t.Fatal("changed mounted key silently accepted")
	}
}

func formRequest(a *App, path string, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", a.publicURL+path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}

func TestDeviceAuthorizationAndRefresh(t *testing.T) {
	a := featureApp(t)
	r := httptest.NewRequest("POST", a.publicURL+"/oauth/register", strings.NewReader(`{"client_name":"remote","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"],"token_endpoint_auth_method":"none"}`))
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	var registration map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &registration)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	clientID := registration["client_id"].(string)
	w = formRequest(a, "/oauth/device/code", url.Values{"client_id": {clientID}, "resource": {a.publicURL + "/mcp"}, "scope": {"mcp"}})
	var device map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &device)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	plain := device["device_code"].(string)
	code := device["user_code"].(string)
	poll := url.Values{"grant_type": {deviceGrantType}, "client_id": {clientID}, "device_code": {plain}, "resource": {a.publicURL + "/mcp"}}
	w = formRequest(a, "/oauth/token", poll)
	if !strings.Contains(w.Body.String(), "authorization_pending") {
		t.Fatal(w.Body.String())
	}
	w = formRequest(a, "/oauth/token", poll)
	if !strings.Contains(w.Body.String(), "slow_down") {
		t.Fatal(w.Body.String())
	}
	// The browser must log in and submit a valid CSRF token to approve.
	get := httptest.NewRequest("GET", a.publicURL+"/oauth/device/verify?user_code="+code, nil)
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, get)
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "next=") {
		t.Fatal("device verification not protected")
	}
	cookies := httptest.NewRecorder()
	session, _ := a.createSession(cookies)
	verify := url.Values{"user_code": {code}, "decision": {"approve"}, "csrf_token": {session.CSRF}}
	r = httptest.NewRequest("POST", a.publicURL+"/oauth/device/verify", strings.NewReader(verify.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", a.publicURL)
	r.AddCookie(cookies.Result().Cookies()[0])
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	_ = a.store.update(func(state *State) error {
		g := state.DeviceGrants[tokenDigest(plain)]
		g.LastPoll = time.Time{}
		state.DeviceGrants[tokenDigest(plain)] = g
		return nil
	})
	wrong := url.Values{"grant_type": {deviceGrantType}, "client_id": {"other"}, "device_code": {plain}}
	w = formRequest(a, "/oauth/token", wrong)
	if w.Code != 400 {
		t.Fatal("cross-client token theft")
	}
	w = formRequest(a, "/oauth/token", poll)
	var tokens tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tokens)
	if w.Code != 200 || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal(w.Body.String())
	}
	if _, ok := a.validBearerToken("Bearer " + tokens.AccessToken); !ok {
		t.Fatal("device access token invalid")
	}
	w = formRequest(a, "/oauth/token", poll)
	if w.Code != 400 {
		t.Fatal("device code replay accepted")
	}
	w = formRequest(a, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.RefreshToken}, "resource": {a.publicURL + "/mcp"}})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	_ = a.store.view(func(state State) error {
		c := state.Clients[clientID]
		if !c.HostAccessConfigured || len(c.AllowedHostIDs) != 0 || !c.RequireApproval {
			t.Fatal("new device client not deny-by-default")
		}
		return nil
	})
}

func TestApprovalExpiryRejectionRestartAndPolicyMigration(t *testing.T) {
	a := featureApp(t)
	host, connections, _ := setupExecution(t, a, true)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "c1")
	rejected, _ := a.submitExecution(ctx, host.ID, "id", 3)
	rejected, err := a.decideAudit(rejected.ID, "deny", "local-admin")
	if err != nil || rejected.Status != "rejected" {
		t.Fatal("rejection failed")
	}
	expired, _ := a.submitExecution(ctx, host.ID, "id", 3)
	a.auditMu.Lock()
	expired.ExpiresAt = time.Now().Add(-time.Second)
	err = a.saveAuditLocked(expired)
	a.auditMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.decideAudit(expired.ID, "approve", "local-admin"); err == nil {
		t.Fatal("expired approval accepted")
	}
	pending, _ := a.submitExecution(ctx, host.ID, "id", 3)
	if err := a.recoverAuditSessions(); err != nil {
		t.Fatal(err)
	}
	pending, err = a.clientAudit(ctx, pending.ID)
	if err != nil || pending.Status != "interrupted" {
		t.Fatal("restart replay protection failed")
	}
	if connections.Load() != 0 {
		t.Fatal("denied/expired/interrupted request connected")
	}
	_ = a.store.update(func(state *State) error { state.Clients["legacy"] = OAuthClient{ID: "legacy"}; return nil })
	if err := migrateClientPolicies(a.store); err != nil {
		t.Fatal(err)
	}
	_ = a.store.update(func(state *State) error { state.Hosts["new"] = Host{ID: "new"}; return nil })
	if err := migrateClientPolicies(a.store); err != nil {
		t.Fatal(err)
	}
	_ = a.store.view(func(state State) error {
		client := state.Clients["legacy"]
		if !client.RequireApproval || !clientAllowsHost(client, host.ID) || clientAllowsHost(client, "new") {
			t.Fatal("legacy migration broadened access")
		}
		return nil
	})
}

func TestDeviceExpiryDenialAndCSRF(t *testing.T) {
	a := featureApp(t)
	_ = a.store.update(func(state *State) error {
		state.Clients["device"] = OAuthClient{ID: "device", DeviceEnabled: true}
		return nil
	})
	for _, tt := range []struct {
		status  string
		expired bool
		want    string
	}{{"pending", true, "expired_token"}, {"denied", false, "access_denied"}} {
		_ = a.store.update(func(state *State) error {
			expires := time.Now().Add(time.Minute)
			if tt.expired {
				expires = time.Now().Add(-time.Second)
			}
			state.DeviceGrants[tokenDigest("device-secret")] = DeviceGrant{ClientID: "device", Status: tt.status, ExpiresAt: expires, Resource: a.publicURL + "/mcp", Interval: 5}
			return nil
		})
		w := formRequest(a, "/oauth/token", url.Values{"grant_type": {deviceGrantType}, "client_id": {"device"}, "device_code": {"device-secret"}})
		if w.Code != 400 || !strings.Contains(w.Body.String(), tt.want) {
			t.Fatalf("device error: %s", w.Body.String())
		}
	}
	cookies := httptest.NewRecorder()
	_, _ = a.createSession(cookies)
	r := httptest.NewRequest("POST", a.publicURL+"/oauth/device/verify", strings.NewReader("decision=approve&user_code=ABCDEFGH"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookies.Result().Cookies()[0])
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("device approval bypassed CSRF")
	}
	for _, path := range []string{"/api/audit", "/api/overview", "/api/keys/some/install", "/api/hosts/probe", "/api/clients/device/policy"} {
		r := httptest.NewRequest("GET", a.publicURL+path, nil)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("management route exposed on public origin: %s", path)
		}
	}
}
