package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Only the jump server knows how to resolve this virtual private-network name.
func jumpFixture(t *testing.T, accepted, target string) (string, string, *atomic.Int32) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != accepted {
			return nil, errors.New("wrong jump key")
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
	active := &atomic.Int32{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			active.Add(1)
			go func() {
				defer active.Add(-1)
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					var dest struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if incoming.ChannelType() != "direct-tcpip" || ssh.Unmarshal(incoming.ExtraData(), &dest) != nil || dest.Host != "private.internal" || dest.Port != 22 {
						_ = incoming.Reject(ssh.Prohibited, "unexpected destination")
						continue
					}
					upstream, err := net.Dial("tcp", target)
					if err != nil {
						_ = incoming.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					channel, reqs, err := incoming.Accept()
					if err != nil {
						_ = upstream.Close()
						continue
					}
					go ssh.DiscardRequests(reqs)
					go func() { defer upstream.Close(); defer channel.Close(); _, _ = io.Copy(upstream, channel) }()
					go func() { defer upstream.Close(); defer channel.Close(); _, _ = io.Copy(channel, upstream) }()
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), active
}

func attachJump(t *testing.T, a *App, host Host) (Host, Host, *atomic.Int32) {
	t.Helper()
	key, err := a.createKey(createKeyRequest{Name: "jump", Source: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	address, fp, active := jumpFixture(t, key.PublicKey, host.Address)
	jump := Host{ID: "jump-" + host.ID, Name: "bastion", Address: address, Username: "jumpuser", KeyID: key.ID, HostKeyFingerprint: fp, TimeoutSeconds: 5}
	host.JumpHostID, host.Address = jump.ID, "private.internal:22"
	if err := a.store.update(func(s *State) error {
		s.Hosts[jump.ID] = jump
		s.Hosts[host.ID] = host
		s.Keys[key.ID] = key
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return host, jump, active
}

func waitJumpClosed(t *testing.T, active *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("jump transport leaked")
	}
}

func TestJumpExecutionProbeAndTrust(t *testing.T) {
	a := featureApp(t)
	h, connections, auths := setupExecution(t, a, false)
	h, jump, active := attachJump(t, a, h)
	ctx := context.WithValue(context.Background(), clientContextKey{}, "c1")
	if health := a.checkHost(ctx, h); health.Status != "online" {
		t.Fatalf("health: %+v", health)
	}
	if auths.Load() != 0 {
		t.Fatal("probe authenticated to target")
	}
	body, _ := json.Marshal(map[string]string{"address": h.Address, "jumpHostId": jump.ID})
	if r := adminRequest(t, a, "POST", "/api/hosts/probe", string(body)); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	result, err := a.submitExecution(ctx, h.ID, "hostname", 3)
	if err != nil || result.ExitCode != 7 || !strings.Contains(result.Stdout, "ran: hostname") {
		t.Fatalf("exec: %+v %v", result, err)
	}
	// A target grant permits transport through the jump, not command access to it.
	if denied, err := a.submitExecution(ctx, jump.ID, "hostname", 3); err != nil || denied.Status != "denied" {
		t.Fatal("jump command access granted implicitly")
	}
	waitJumpClosed(t, active)
	wrongTarget := h
	wrongTarget.HostKeyFingerprint = jump.HostKeyFingerprint
	var targetKey StoredKey
	_ = a.store.view(func(s State) error { targetKey = s.Keys[h.KeyID]; return nil })
	if _, _, err := a.runSSHCommand(ctx, wrongTarget, targetKey, "hostname", 3, &AuditSession{}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("target trust: %v", err)
	}
	waitJumpClosed(t, active)
	before := connections.Load()
	jump.HostKeyFingerprint = h.HostKeyFingerprint
	_ = a.store.update(func(s *State) error { s.Hosts[jump.ID] = jump; return nil })
	if _, _, err := a.probeHost(ctx, h); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("jump trust: %v", err)
	}
	if connections.Load() != before {
		t.Fatal("reached target despite wrong jump fingerprint")
	}
	waitJumpClosed(t, active)
}

func TestJumpPersistentAndMultiHop(t *testing.T) {
	a, h, ctx, _, _ := persistentFixture(t)
	h, jump, active := attachJump(t, a, h)
	_, _, outerActive := attachJump(t, a, jump)
	open, err := a.submitOperation(ctx, h.ID, "[open persistent shell]", 0, "open", "")
	if err != nil || open.Status != "completed" {
		t.Fatalf("open: %+v %v", open, err)
	}
	for _, cmd := range []string{"export JUMP_TEST=works", `printf '%s' "$JUMP_TEST"`} {
		result, err := a.submitOperation(ctx, h.ID, cmd, 3, "exec", open.ConnectionID)
		if err != nil || result.Status != "completed" {
			t.Fatalf("exec: %+v %v", result, err)
		}
		if strings.HasPrefix(cmd, "printf") && result.Stdout != "works" {
			t.Fatal(result.Stdout)
		}
	}
	a.closeAllConnections("test close")
	waitJumpClosed(t, active)
	waitJumpClosed(t, outerActive)
}

func TestJumpValidationAndCancellation(t *testing.T) {
	a := featureApp(t)
	h, _, _ := setupExecution(t, a, false)
	h, jump, active := attachJump(t, a, h)
	r := adminRequest(t, a, "DELETE", "/api/hosts/"+jump.ID, "")
	if r.Code < 400 {
		t.Fatal("deleted referenced jump")
	}
	body, _ := json.Marshal(createHostRequest{Name: "bad", Address: h.Address, Username: h.Username, KeyID: h.KeyID, HostKeyFingerprint: h.HostKeyFingerprint, JumpHostID: "missing"})
	if r := adminRequest(t, a, "POST", "/api/hosts", string(body)); r.Code != 400 {
		t.Fatal(r.Code, r.Body.String())
	}
	valid := createHostRequest{Name: "via jump", Address: h.Address, Username: h.Username, KeyID: h.KeyID, HostKeyFingerprint: h.HostKeyFingerprint, JumpHostID: jump.ID}
	body, _ = json.Marshal(valid)
	created := adminRequest(t, a, "POST", "/api/hosts", string(body))
	var saved publicHost
	if err := json.Unmarshal(created.Body.Bytes(), &saved); err != nil || created.Code != 201 || saved.JumpHostID != jump.ID {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	reopened, err := openStore(filepath.Dir(a.store.path))
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.view(func(s State) error {
		if s.Hosts[saved.ID].JumpHostID != jump.ID {
			t.Fatal("jump config not persisted")
		}
		return nil
	})
	s := State{Hosts: map[string]Host{jump.ID: jump}}
	cyclic := jump
	cyclic.JumpHostID = jump.ID
	s.Hosts[jump.ID] = cyclic
	if _, err := jumpRoute(s, h); err == nil {
		t.Fatal("accepted cycle")
	}
	// The forwarded TCP peer accepts but never speaks SSH: cancellation must
	// interrupt the target handshake and release the authenticated jump.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	h.Address = listener.Addr().String()
	h, _, active = attachJump(t, a, h)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := a.probeHost(ctx, h); err == nil {
		t.Fatal("stalled handshake succeeded")
	}
	waitJumpClosed(t, active)
}
