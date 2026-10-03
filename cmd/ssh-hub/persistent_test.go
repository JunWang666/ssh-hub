package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func shellFixture(t *testing.T, accepted string) (string, string, *atomic.Int32, func()) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) != accepted {
			return nil, errors.New("invalid key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := func() { cancel(); _ = listener.Close() }
	t.Cleanup(stop)
	count := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer conn.Close()
				c, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer c.Close()
				stopClose := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stopClose()
				shellCtx, shellCancel := context.WithCancel(ctx)
				defer shellCancel()
				go func() { _ = c.Wait(); shellCancel() }()
				go func() {
					for r := range reqs {
						_ = r.Reply(false, nil)
					}
				}()
				for incoming := range chans {
					ch, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					go func() {
						defer ch.Close()
						for req := range requests {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &payload)
							if payload.Command != "sh" {
								_ = req.Reply(false, nil)
								return
							}
							_ = req.Reply(true, nil)
							cmd := exec.CommandContext(shellCtx, "sh")
							cmd.Stdin = ch
							cmd.Stdout = ch
							cmd.Stderr = ch.Stderr()
							cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
							cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
							cmd.WaitDelay = time.Second
							err := cmd.Run()
							status := uint32(0)
							if err != nil {
								status = 1
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), count, stop
}
func persistentFixture(t *testing.T) (*App, Host, context.Context, *atomic.Int32, func()) {
	t.Helper()
	a := featureApp(t)
	key, err := a.createKey(createKeyRequest{Name: "shell", Source: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	address, fp, count, stop := shellFixture(t, key.PublicKey)
	host := Host{ID: "persistent-host", Name: "shell", Address: address, Username: "test", KeyID: key.ID, HostKeyFingerprint: fp, TimeoutSeconds: 5}
	err = a.store.update(func(s *State) error {
		s.Hosts[host.ID] = host
		s.Clients["owner"] = OAuthClient{ID: "owner", HostAccessConfigured: true, AllowedHostIDs: []string{host.ID}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.closeAllConnections("test cleanup") })
	return a, host, context.WithValue(context.Background(), clientContextKey{}, "owner"), count, stop
}
func TestPersistentShellStateAuditAndHealth(t *testing.T) {
	a, h, ctx, count, stop := persistentFixture(t)
	open, err := a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil || open.Status != "completed" {
		t.Fatalf("open: %+v %v", open, err)
	}
	id := open.ConnectionID
	run := func(command string) AuditSession {
		t.Helper()
		r, err := a.submitOperation(ctx, h.ID, command, 3, "exec", id)
		if err != nil || r.Status != "completed" {
			t.Fatalf("exec: %+v %v", r, err)
		}
		return r
	}
	run("cd /tmp; export SSHHUB_TEST_STATE=persisted")
	r := run("printf '%s:%s' \"$PWD\" \"$SSHHUB_TEST_STATE\"; printf 'separate-error' >&2")
	if r.Stdout != "/tmp:persisted" || r.Stderr != "separate-error" {
		t.Fatalf("state/output: %+v", r)
	}
	run("(sleep 0.1; printf 'background-result') &")
	time.Sleep(200 * time.Millisecond)
	r = run("printf 'next-command'")
	if !strings.Contains(r.Stdout, "next-command") {
		t.Fatal(r.Stdout)
	}
	if count.Load() != 1 {
		t.Fatal("connection was not reused")
	}
	p, err := a.connection("owner", id)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.checkConnection(ctx, p); got.Status != "open" || got.CheckedAt.IsZero() {
		t.Fatalf("keepalive %+v", got)
	}
	transcript, err := a.readTranscript("owner", id, 0)
	if err != nil || !strings.Contains(transcript["data"].(string), "background-result") {
		t.Fatalf("transcript %v %v", transcript, err)
	}
	if _, err = a.readTranscript("other", id, 0); err == nil {
		t.Fatal("cross-client transcript exposed")
	}
	if _, err = a.connection("other", id); err == nil {
		t.Fatal("cross-client session exposed")
	}
	records, _, err := a.clientAuditList("owner", "", id, "")
	if err != nil || len(records) != 5 {
		t.Fatalf("audit list %d %v", len(records), err)
	}
	other, _, _ := a.clientAuditList("other", "", id, "")
	if len(other) != 0 {
		t.Fatal("cross-client audit list exposed")
	}
	restart := newApp(a.store, a.publicURL)
	if _, err = restart.readTranscript("owner", id, 0); err != nil {
		t.Fatal("persisted transcript unreadable", err)
	}
	health := a.checkHost(ctx, h)
	if health.Status != "online" {
		t.Fatalf("host health %+v", health)
	}
	h.HostKeyFingerprint = "SHA256:incorrect"
	if got := a.checkHost(ctx, h); got.Status != "fingerprint_changed" {
		t.Fatal(got)
	}
	stop()
	deadline := time.Now().Add(3 * time.Second)
	for p.snapshot().Status != "closed" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.snapshot().Status != "closed" {
		t.Fatal("disconnect not detected")
	}
	before := count.Load()
	r, err = a.submitOperation(ctx, h.ID, "id", 1, "exec", id)
	if err != nil || r.Status != "failed" || count.Load() != before {
		t.Fatalf("closed shell reconnected %+v %v", r, err)
	}
}
func TestPersistentApprovalIsolationTimeoutAndRevocation(t *testing.T) {
	a, h, ctx, count, _ := persistentFixture(t)
	_ = a.store.update(func(s *State) error {
		c := s.Clients["owner"]
		c.RequireApproval = true
		s.Clients[c.ID] = c
		return nil
	})
	r, err := a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil || r.Status != "pending" || count.Load() != 0 {
		t.Fatal("connected before approval")
	}
	r, err = a.decideAudit(r.ID, "approve", "admin")
	if err != nil {
		t.Fatal(err)
	}
	r = a.executeAudited(ctx, r)
	if r.Status != "completed" {
		t.Fatal(r)
	}
	pending, err := a.submitOperation(ctx, h.ID, "export PERSIST_APPROVAL=yes", 1, "exec", r.ConnectionID)
	if err != nil || pending.Status != "pending" {
		t.Fatal("execution bypassed approval")
	}
	p, _ := a.connection("owner", r.ConnectionID)
	p.execMu.Lock()
	pending.Status = "running"
	busy := a.executeAudited(ctx, pending)
	p.execMu.Unlock()
	if busy.Status != "failed" || !strings.Contains(busy.Error, "busy") {
		t.Fatal(busy)
	}
	_ = a.store.update(func(s *State) error {
		c := s.Clients["owner"]
		c.RequireApproval = false
		s.Clients[c.ID] = c
		return nil
	})
	timed, err := a.submitOperation(ctx, h.ID, "sleep 30", 1, "exec", r.ConnectionID)
	if err != nil || timed.ExitCode != 124 || p.snapshot().Status != "closed" {
		t.Fatalf("timeout %+v %v", timed, err)
	}
	r, err = a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil || r.Status != "completed" {
		t.Fatal(r, err)
	}
	p, _ = a.connection("owner", r.ConnectionID)
	_ = a.store.update(func(s *State) error { delete(s.Clients, "owner"); return nil })
	if a.checkConnection(ctx, p).Status != "closed" {
		t.Fatal("revocation left connection open")
	}
}
func TestAuditMCPAndHealthAPIIsolation(t *testing.T) {
	a, h, ctx, _, _ := persistentFixture(t)
	r, err := a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh_audit_list", "ssh_audit_read", "ssh_list_sessions", "ssh_check_session", "ssh_read_session"} {
		args, _ := json.Marshal(map[string]string{"session_id": r.ID, "connection_id": r.ConnectionID})
		out, rpc := a.callPersistentTool(name, args, ctx)
		if rpc != nil || out.(map[string]any)["isError"] == true {
			t.Fatalf("%s: %v %v", name, out, rpc)
		}
	}
	other := context.WithValue(context.Background(), clientContextKey{}, "other")
	for _, name := range []string{"ssh_audit_read", "ssh_check_session", "ssh_close_session", "ssh_read_session"} {
		args, _ := json.Marshal(map[string]string{"session_id": r.ID, "connection_id": r.ConnectionID})
		out, _ := a.callPersistentTool(name, args, other)
		if out.(map[string]any)["isError"] != true {
			t.Fatal("cross-client access", name)
		}
	}
	w := adminRequest(t, a, "POST", "/api/hosts/"+h.ID+"/health", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "online") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = adminRequest(t, a, "POST", "/api/connections/"+r.ConnectionID+"/check", "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = adminRequest(t, a, "DELETE", "/api/connections/"+r.ConnectionID, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "closed") {
		t.Fatal(w.Body.String())
	}
}

func TestPersistentTranscriptFailureClosesShell(t *testing.T) {
	a, h, ctx, _, _ := persistentFixture(t)
	r, err := a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil || r.Status != "completed" {
		t.Fatal(r, err)
	}
	p, _ := a.connection("owner", r.ConnectionID)
	p.transcriptMu.Lock()
	p.transcriptBytes = 16 * 1024 * 1024
	p.transcriptMu.Unlock()
	result, err := a.submitOperation(ctx, h.ID, "printf unrecordable", 3, "exec", r.ConnectionID)
	if err != nil || result.Status != "failed" || p.snapshot().Status != "closed" {
		t.Fatalf("transcript failure did not close shell: %+v %v", result, err)
	}
	if result.ExitCode == 124 {
		t.Fatal("output failure waited for timeout instead of closing immediately")
	}
}
