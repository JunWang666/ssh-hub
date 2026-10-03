package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteDeviceLoginAndStdioBridge(t *testing.T) {
	a := featureApp(t)
	a.adminURL = ""
	deviceReady := make(chan string, 1)
	routes := a.routes()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/device/code" {
			recorder := httptest.NewRecorder()
			routes.ServeHTTP(recorder, r)
			for key, values := range recorder.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			var result struct {
				Code string `json:"user_code"`
			}
			_ = json.Unmarshal(recorder.Body.Bytes(), &result)
			deviceReady <- result.Code
			return
		}
		routes.ServeHTTP(w, r)
	}))
	defer server.Close()
	a.publicURL = "http://" + server.Listener.Addr().String()
	server.Start()
	t.Setenv("SSHHUB_CREDENTIALS_DIR", t.TempDir())
	client, err := newHubClient(server.URL, "agent-test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := client.credentials(ctx, true, false); finished <- err }()
	select {
	case code := <-deviceReady:
		if code == "" {
			t.Fatal("device authorization did not start")
		}
		if err := a.store.update(func(state *State) error {
			for digest, grant := range state.DeviceGrants {
				if grant.UserCode == normalizeUserCode(code) {
					grant.Status = "approved"
					state.DeviceGrants[digest] = grant
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(client.credentialsPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credentials permissions incorrect")
	}
	creds, err := client.credentials(ctx, false, false)
	if err != nil {
		t.Fatal(err)
	}
	oldRefresh := creds.RefreshToken
	creds.ExpiresAt = time.Now().Add(-time.Minute)
	if err := client.saveCredentials(creds); err != nil {
		t.Fatal(err)
	}
	creds, err = client.credentials(ctx, false, false)
	if err != nil || creds.RefreshToken == oldRefresh {
		t.Fatalf("automatic refresh failed: %v", err)
	}
	var output bytes.Buffer
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ssh_list_hosts\",\"arguments\":{}}}\n")
	if err := client.bridge(ctx, input, &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("unexpected stdio output: %s", output.String())
	}
	for _, line := range lines {
		var response jsonRPCResponse
		if json.Unmarshal([]byte(line), &response) != nil || response.JSONRPC != "2.0" || response.Error != nil {
			t.Fatalf("invalid stdio response: %s", line)
		}
	}
	if strings.Contains(output.String(), creds.AccessToken) || strings.Contains(output.String(), "等待") {
		t.Fatal("credential or login message leaked to stdio")
	}
}

func TestStdioDoesNotRetryExecutionOnTransportError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unavailable", 503) }))
	defer server.Close()
	t.Setenv("SSHHUB_CREDENTIALS_DIR", t.TempDir())
	client, err := newHubClient(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.saveCredentials(clientCredentials{ClientID: "c", AccessToken: "test-token", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := client.bridge(context.Background(), strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ssh_exec\"}}\n"), &output); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !strings.Contains(output.String(), "not retried") {
		t.Fatalf("execution retry policy failed: %d %s", calls.Load(), output.String())
	}
}
