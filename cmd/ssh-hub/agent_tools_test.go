package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func agentCall(t *testing.T, a *App, ctx context.Context, req agentRequest) (map[string]any, bool) {
	t.Helper()
	b, _ := json.Marshal(req)
	params, _ := json.Marshal(map[string]any{"name": "ssh_agent", "arguments": json.RawMessage(b)})
	response, rpcErr := a.callTool(params, ctx)
	if rpcErr != nil {
		t.Fatalf("rpc: %+v", rpcErr)
	}
	envelope := response.(map[string]any)
	content := envelope["content"].([]map[string]string)[0]["text"]
	var result map[string]any
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return map[string]any{"error": content}, true
	}
	isErr, _ := envelope["isError"].(bool)
	if _, ok := envelope["structuredContent"]; ok {
		t.Fatal("agent result duplicated in structuredContent")
	}
	return result, isErr
}

func TestAgentSchemaAndValidation(t *testing.T) {
	count := 0
	for _, tool := range toolDefinitions() {
		if strings.Contains(tool["name"].(string), "agent") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one agent tool, got %d", count)
	}
	for _, raw := range []string{
		`{}`, `null`, `{"action":"invalid"}`, `{"action":"start","host_id":"h","cwd":"relative"}`,
		`{"action":"start","host_id":"h","cwd":"/tmp","kind":"sh"}`,
		`{"action":"status","host_id":"h","agent_id":"--help"}`,
		`{"action":"stop","host_id":"h"}`, `{"action":"prompt","host_id":"h","agent_id":"agent"}`,
		`{"action":"keys","host_id":"h","agent_id":"agent","keys":["$(touch /tmp/pwn)"]}`,
		`{"action":"read","host_id":"h","agent_id":"agent","lines":201}`,
		`{"action":"list","host_id":"h","timeout_seconds":61}`, `{"action":"list","host_id":"h","offset":-1}`,
		`{"action":"list","host_id":"h","until":"idle"}`, `{"action":"result","session_id":"bad"}`,
		`{"action":"list","host_id":"h","extra":"ignored?"}`, `{"action":"list","host_id":"h"} {}`,
	} {
		if _, err := decodeAgentRequest([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`{"action":"start","host_id":"h","cwd":"/tmp/quote'$(whoami)","text":"--literal\nhello"}`, `{"action":"read","host_id":"h","agent_id":"w1:p2"}`, `{"action":"keys","host_id":"h","agent_id":"worker","keys":["down","enter"]}`} {
		if _, err := decodeAgentRequest([]byte(raw)); err != nil {
			t.Errorf("rejected %s: %v", raw, err)
		}
	}
}

func TestAgentApprovalIsolationAndRestart(t *testing.T) {
	a := featureApp(t)
	h, connections, _ := setupExecution(t, a, true)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "c1")
	req := agentRequest{Action: "start", HostID: h.ID, Cwd: "/tmp", Text: "review code"}
	pending, isErr := agentCall(t, a, ctx, req)
	if isErr || pending["status"] != "pending" || pending["agent_id"] == "" {
		t.Fatalf("pending %+v", pending)
	}
	id := pending["session_id"].(string)
	if connections.Load() != 0 {
		t.Fatal("connected before approval")
	}
	poll, isErr := agentCall(t, a, ctx, agentRequest{Action: "result", SessionID: id})
	if isErr || poll["status"] != "pending" {
		t.Fatal(poll)
	}
	other := context.WithValue(context.Background(), clientContextKey{}, "c2")
	if _, isErr := agentCall(t, a, other, agentRequest{Action: "result", SessionID: id}); !isErr {
		t.Fatal("cross-client audit exposed")
	}
	denied, isErr := agentCall(t, a, other, agentRequest{Action: "list", HostID: h.ID})
	if !isErr || denied["status"] != "denied" || connections.Load() != 0 {
		t.Fatal(denied)
	}
	// Namespace survives Hub restart and differs across hosts, clients and Hubs.
	restarted := newApp(a.store, a.publicURL)
	if a.agentNamespace("c1", h.ID) != restarted.agentNamespace("c1", h.ID) {
		t.Fatal("namespace changed on restart")
	}
	if a.agentNamespace("c1", h.ID) == a.agentNamespace("c2", h.ID) || a.agentNamespace("c1", h.ID) == a.agentNamespace("c1", "other") || a.agentNamespace("c1", h.ID) == featureApp(t).agentNamespace("c1", h.ID) {
		t.Fatal("namespace collision")
	}
	// Revocation after submission must prevent approved execution too.
	_ = a.store.update(func(s *State) error { c := s.Clients["c1"]; c.AllowedHostIDs = nil; s.Clients["c1"] = c; return nil })
	decided, err := a.decideAudit(id, "approve", "test-admin")
	if err != nil || decided.Status != "denied" || connections.Load() != 0 {
		t.Fatalf("decision %+v %v", decided, err)
	}
	poll, isErr = agentCall(t, restarted, ctx, agentRequest{Action: "result", SessionID: id})
	if !isErr || poll["status"] != "denied" {
		t.Fatal(poll)
	}
}

// Executes controller commands on a temporary local SSH server. No production
// credentials or model endpoints are used, even in the optional Herdr test.
func agentSSHFixture(t *testing.T, accepted string, env []string) (string, string) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != accepted {
			return nil, errors.New("wrong key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				childCtx, childCancel := context.WithCancel(ctx)
				defer childCancel()
				go func() { _ = server.Wait(); childCancel() }()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						var payload struct{ Command string }
						_ = ssh.Unmarshal(request.Payload, &payload)
						_ = request.Reply(true, nil)
						command := exec.CommandContext(childCtx, "sh", "-c", payload.Command)
						command.Env = env
						command.Stdout = channel
						command.Stderr = channel.Stderr()
						command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
						command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
						code := uint32(0)
						if err := command.Run(); err != nil {
							code = 1
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
						_ = channel.Close()
						break
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func TestAgentHerdrIntegration(t *testing.T) {
	binary := os.Getenv("SSHHUB_TEST_HERDR")
	if binary == "" {
		t.Skip("set SSHHUB_TEST_HERDR to test real Herdr with a simulated agent")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "hub-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	bin := filepath.Join(root, ".local", "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(bin, "herdr")); err != nil {
		t.Fatal(err)
	}
	// The mock emits Herdr state reports and echoes input. It is not a real Codex
	// process and never reads user credentials or contacts a model.
	mock := `#!/usr/bin/python3
import os,subprocess,sys,time,signal
signal.signal(signal.SIGINT,lambda *args: print('INTERRUPTED',flush=True))
def report(state):
 subprocess.run(['herdr','pane','report-agent',os.environ['HERDR_PANE_ID'],'--source','hub-test','--agent','codex','--state',state],stdout=subprocess.DEVNULL)
print('TEST-AGENT-READY',flush=True)
report('idle')
for line in sys.stdin:
 report('working')
 print('RECEIVED:'+line.strip(),flush=True)
 time.sleep(0.05)
 report('idle')
`
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(mock), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config.toml")
	_ = os.WriteFile(config, []byte("onboarding = false\n[terminal]\ndefault_shell = \"/bin/sh\"\n[update]\nversion_check = false\nmanifest_check = false\n"), 0600)
	runtime := filepath.Join(root, "run")
	_ = os.Mkdir(runtime, 0700)
	env := []string{"HOME=" + root, "PATH=" + bin + ":/usr/bin:/bin", "SHELL=/bin/sh", "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_STATE_HOME=" + filepath.Join(root, "state"), "XDG_RUNTIME_DIR=" + runtime, "HERDR_CONFIG_PATH=" + config, "TERM=xterm-256color"}
	a := featureApp(t)
	key, err := a.createKey(createKeyRequest{Name: "agent", Source: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	address, fp := agentSSHFixture(t, key.PublicKey, env)
	h := Host{ID: "agent-host", Name: "agent host", Address: address, Username: "tester", KeyID: key.ID, HostKeyFingerprint: fp, TimeoutSeconds: 30}
	_ = a.store.update(func(s *State) error {
		s.Hosts[h.ID] = h
		s.Clients["owner"] = OAuthClient{ID: "owner", HostAccessConfigured: true, AllowedHostIDs: []string{h.ID}}
		s.Clients["other"] = OAuthClient{ID: "other", HostAccessConfigured: true, AllowedHostIDs: []string{h.ID}}
		return nil
	})
	h, _, active := attachJump(t, a, h)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "owner")
	t.Cleanup(func() {
		cmd := exec.Command(binary, "--session", a.agentNamespace("owner", h.ID), "server", "stop")
		cmd.Env = env
		_ = cmd.Run()
	})
	call := func(req agentRequest) map[string]any {
		t.Helper()
		req.HostID = h.ID
		res, failed := agentCall(t, a, ctx, req)
		if failed {
			t.Fatalf("%s: %+v", req.Action, res)
		}
		return res
	}
	start := call(agentRequest{Action: "start", Cwd: root, Text: "first prompt"})
	id := start["agent_id"].(string)
	if start["result"].(map[string]any)["prompt_submitted"] != true {
		t.Fatal(start)
	}
	// Every controller request closes its SSH connection; the agent remains live.
	waitJumpClosed(t, active)
	// Server restart of Hub preserves routing and ownership without keeping SSH alive.
	a = newApp(a.store, a.publicURL)
	list := call(agentRequest{Action: "list"})
	if list["result"].(map[string]any)["total"] != float64(1) {
		t.Fatal(list)
	}
	call(agentRequest{Action: "status", AgentID: id})
	// Preserve quotes, shell syntax, option-like text, Unicode and newlines exactly.
	sentinel := filepath.Join(root, "injected")
	text := "--literal '中文' $(touch " + sentinel + ") `touch " + sentinel + "`\nsecond line"
	call(agentRequest{Action: "prompt", AgentID: id, Text: text})
	deadline := time.Now().Add(4 * time.Second)
	for {
		read := call(agentRequest{Action: "read", AgentID: id, Lines: 200})
		output := read["result"].(map[string]any)["output"].(string)
		if strings.Contains(output, "second line") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing prompt: %s", output)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("shell injection", err)
	}
	call(agentRequest{Action: "keys", AgentID: id, Keys: []string{"enter"}})
	call(agentRequest{Action: "wait", AgentID: id, Until: "idle", TimeoutSeconds: 5})
	waitResult := call(agentRequest{Action: "wait", AgentID: id, Until: "blocked", TimeoutSeconds: 5})
	if waitResult["result"].(map[string]any)["timed_out"] != true {
		t.Fatal(waitResult)
	}
	otherCtx := context.WithValue(context.Background(), clientContextKey{}, "other")
	if _, failed := agentCall(t, a, otherCtx, agentRequest{Action: "stop", HostID: h.ID, AgentID: id}); !failed {
		t.Fatal("other client controlled agent")
	}
	// Retrying start with the returned name cannot create a second agent or resend text.
	duplicate, failed := agentCall(t, a, ctx, agentRequest{Action: "start", HostID: h.ID, Cwd: root, AgentID: id, Text: "duplicate"})
	if !failed || duplicate["result"].(map[string]any)["error"].(map[string]any)["code"] != "already_exists" {
		t.Fatal(duplicate)
	}
	call(agentRequest{Action: "interrupt", AgentID: id})
	call(agentRequest{Action: "stop", AgentID: id})
	list = call(agentRequest{Action: "list"})
	if list["result"].(map[string]any)["total"] != float64(0) {
		t.Fatal(list)
	}
	record, err := a.clientAudit(ctx, start["session_id"].(string))
	if err != nil || record.Operation != "agent" || !strings.Contains(record.Command, "first prompt") {
		t.Fatalf("audit %+v %v", record, err)
	}
	result, failed := agentCall(t, a, ctx, agentRequest{Action: "result", SessionID: record.ID})
	if failed || result["status"] != "completed" {
		t.Fatal(result)
	}
}

func TestAgentApprovedFailureDoesNotReplay(t *testing.T) {
	a := featureApp(t)
	h, connections, _ := setupExecution(t, a, true)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "c1")
	pending, failed := agentCall(t, a, ctx, agentRequest{Action: "status", HostID: h.ID, AgentID: "worker"})
	if failed || pending["status"] != "pending" {
		t.Fatal(pending)
	}
	id := pending["session_id"].(string)
	approved, err := a.decideAudit(id, "approve", "test-admin")
	if err != nil || approved.Status != "running" {
		t.Fatal(approved, err)
	}
	// This fixture returns plain shell output rather than controller JSON. Treat
	// malformed output as failure, preserving the audit instead of replaying.
	completed := a.executeAudited(ctx, approved)
	if completed.Status != "failed" || connections.Load() != 1 {
		t.Fatalf("%+v connections=%d", completed, connections.Load())
	}
	for i := 0; i < 2; i++ {
		polled, failed := agentCall(t, a, ctx, agentRequest{Action: "result", SessionID: id})
		if !failed || polled["status"] != "failed" {
			t.Fatal(polled)
		}
	}
	if connections.Load() != 1 {
		t.Fatal("result replayed remote operation")
	}
}
