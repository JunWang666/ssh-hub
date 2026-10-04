package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type ConnectionInfo struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"clientId"`
	HostID     string    `json:"hostId"`
	HostName   string    `json:"hostName"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	CheckedAt  time.Time `json:"checkedAt"`
	ClosedAt   time.Time `json:"closedAt,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type persistentConnection struct {
	app             *App
	clientName      string
	mu              sync.Mutex
	execMu          sync.Mutex
	checkMu         sync.Mutex
	once            sync.Once
	info            ConnectionInfo
	host            Host
	client          *ssh.Client
	shell           *ssh.Session
	stdin           io.WriteCloser
	stdout, stderr  *shellStream
	done            chan struct{}
	transcriptMu    sync.Mutex
	transcript      *os.File
	transcriptBytes int64
}

type shellFrame struct {
	status int
	stream string
}
type shellStream struct {
	mu      sync.Mutex
	owner   *persistentConnection
	name    string
	marker  []byte
	pending []byte
	capture *outputBuffer
	frames  chan shellFrame
}

// Recognize a random per-command marker across arbitrary SSH packet boundaries.
// Everything else, including output between commands, goes to the transcript.
func (s *shellStream) Write(p []byte) (written int, writeErr error) {
	defer func() {
		if writeErr != nil {
			s.owner.close("shell output persistence failed: " + writeErr.Error())
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(p)
	s.pending = append(s.pending, p...)
	for len(s.pending) > 0 {
		if len(s.marker) == 0 {
			if err := s.emit(s.pending); err != nil {
				return 0, err
			}
			s.pending = nil
			break
		}
		i := bytes.Index(s.pending, s.marker)
		if i < 0 {
			keep := len(s.marker) - 1
			if len(s.pending) <= keep {
				break
			}
			cut := len(s.pending) - keep
			if err := s.emit(s.pending[:cut]); err != nil {
				return 0, err
			}
			s.pending = append([]byte(nil), s.pending[cut:]...)
			break
		}
		if i > 0 {
			if err := s.emit(s.pending[:i]); err != nil {
				return 0, err
			}
			s.pending = s.pending[i:]
		}
		rest := s.pending[len(s.marker):]
		end := bytes.IndexByte(rest, 0x1f)
		if end < 0 && len(rest) < 16 {
			break
		}
		if end < 0 || end > 3 {
			return 0, errors.New("invalid shell completion frame")
		}
		status, err := strconv.Atoi(string(rest[:end]))
		if err != nil || status < 0 || status > 255 {
			return 0, errors.New("invalid shell exit status")
		}
		s.pending = append([]byte(nil), rest[end+1:]...)
		s.marker = nil
		s.capture = nil
		s.frames <- shellFrame{status: status, stream: s.name}
	}
	return n, nil
}
func (s *shellStream) emit(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if err := s.owner.appendTranscript(s.name, p); err != nil {
		return err
	}
	if s.capture != nil {
		_, _ = s.capture.Write(p)
	}
	return nil
}
func (s *shellStream) begin(marker string, capture *outputBuffer, frames chan shellFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.emit(s.pending); err != nil {
		return err
	}
	s.pending = nil
	s.marker = []byte("\x1e" + marker + ":")
	s.capture = capture
	s.frames = frames
	return nil
}
func (s *shellStream) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.emit(s.pending)
	s.pending = nil
}
func (p *persistentConnection) appendTranscript(stream string, data []byte) error {
	p.transcriptMu.Lock()
	defer p.transcriptMu.Unlock()
	entry, _ := json.Marshal(map[string]any{"at": time.Now().UTC(), "stream": stream, "data": string(data)})
	entry = append(entry, '\n')
	if p.transcriptBytes+int64(len(entry)) > 16*1024*1024 {
		return errors.New("session transcript limit (16 MiB) reached; open a new session")
	}
	if _, err := p.transcript.Write(entry); err != nil {
		return err
	}
	if err := p.transcript.Sync(); err != nil {
		return err
	}
	p.transcriptBytes += int64(len(entry))
	return nil
}
func (p *persistentConnection) snapshot() ConnectionInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info
}
func (p *persistentConnection) close(reason string) {
	p.once.Do(func() {
		_ = p.appendTranscript("lifecycle", []byte(reason))
		p.mu.Lock()
		p.info.Status = "closed"
		p.info.Error = reason
		p.info.ClosedAt = time.Now().UTC()
		p.mu.Unlock()
		close(p.done)
		_ = p.client.Close()
		p.app.recordConnectionClose(p.snapshot(), p.host, p.clientName, reason)
	})
}
func (a *App) connection(clientID, id string) (*persistentConnection, error) {
	a.connectionsMu.Lock()
	p := a.connections[id]
	a.connectionsMu.Unlock()
	if p == nil || (clientID != "" && p.snapshot().ClientID != clientID) {
		return nil, errors.New("persistent session not found")
	}
	return p, nil
}
func (a *App) openPersistent(ctx context.Context, host Host, key StoredKey, record *AuditSession) error {
	// Reserve a slot before dialing. Closed sessions are retained for inspection until capacity is needed.
	a.connectionsMu.Lock()
	if len(a.connections) >= 128 {
		for id, p := range a.connections {
			if p.snapshot().Status == "closed" {
				delete(a.connections, id)
			}
		}
	}
	if len(a.connections) >= 128 {
		a.connectionsMu.Unlock()
		return errors.New("persistent session capacity reached")
	}
	p := &persistentConnection{app: a, clientName: record.ClientName, host: host, done: make(chan struct{}), info: ConnectionInfo{ID: record.ConnectionID, ClientID: record.ClientID, HostID: host.ID, HostName: host.Name, Status: "connecting", CreatedAt: time.Now().UTC(), LastUsedAt: time.Now().UTC()}}
	// Connecting entries are not exposed to check/close handlers until initialized.
	a.connections[record.ConnectionID] = p
	a.connectionsMu.Unlock()
	success := false
	defer func() {
		if !success {
			a.connectionsMu.Lock()
			delete(a.connections, record.ConnectionID)
			a.connectionsMu.Unlock()
		}
	}()
	signer, err := a.keySigner(key)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := a.dialHostTransport(dialCtx, host)
	if err != nil {
		return err
	}
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := dialCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	cfg := &ssh.ClientConfig{User: host.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(host.HostKeyFingerprint)) != 1 {
			return errors.New("SSH server host key fingerprint mismatch")
		}
		return nil
	}}
	cc, chans, reqs, err := ssh.NewClientConn(conn, host.Address, cfg)
	if err != nil {
		return err
	}
	p.client = ssh.NewClient(cc, chans, reqs)
	p.shell, err = p.client.NewSession()
	if err != nil {
		return err
	}
	p.stdin, err = p.shell.StdinPipe()
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(a.store.path), "transcripts")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	p.transcript, err = os.OpenFile(filepath.Join(dir, record.ConnectionID+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if !success {
			_ = p.transcript.Close()
		}
	}()
	p.stdout = &shellStream{owner: p, name: "stdout"}
	p.stderr = &shellStream{owner: p, name: "stderr"}
	p.shell.Stdout = p.stdout
	p.shell.Stderr = p.stderr
	if err = p.shell.Start("sh"); err != nil {
		return err
	}
	if p.snapshot().Status == "closed" {
		return errors.New("shell closed during startup")
	}
	if !stop() || dialCtx.Err() != nil {
		return errors.New("SSH shell connection cancelled")
	}
	_ = conn.SetDeadline(time.Time{})
	p.mu.Lock()
	p.info.Status = "open"
	p.mu.Unlock()
	_, current, _, accessErr := a.resolveExecution(record.ClientID, host.ID)
	if accessErr != nil || current != host {
		p.close("host access changed during connection")
		return errors.New("host access changed during connection")
	}
	success = true
	go func() {
		err := p.shell.Wait()
		p.stdout.flush()
		p.stderr.flush()
		reason := "remote shell exited"
		if err != nil {
			reason = err.Error()
		}
		p.close(reason)
		p.transcriptMu.Lock()
		_ = p.transcript.Close()
		p.transcriptMu.Unlock()
	}()
	return nil
}

func (a *App) runPersistent(ctx context.Context, host Host, record *AuditSession) (string, int, error) {
	p, err := a.connection(record.ClientID, record.ConnectionID)
	if err != nil {
		return "", -1, err
	}
	if !p.execMu.TryLock() {
		return "", -1, errors.New("session is busy; wait for the current command")
	}
	defer p.execMu.Unlock()
	p.mu.Lock()
	if p.info.Status != "open" || p.host != host {
		p.mu.Unlock()
		return "", -1, errors.New("session is closed or host configuration changed")
	}
	p.info.Status = "busy"
	p.info.LastUsedAt = time.Now().UTC()
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.info.Status == "busy" {
			p.info.Status = "open"
		}
		p.info.LastUsedAt = time.Now().UTC()
		p.mu.Unlock()
	}()
	timeout := host.TimeoutSeconds
	if record.TimeoutSeconds > 0 && record.TimeoutSeconds < timeout {
		timeout = record.TimeoutSeconds
	}
	if timeout < 1 || timeout > 300 {
		timeout = 30
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	stdout, stderr := &outputBuffer{limit: maxCommandOutput}, &outputBuffer{limit: maxCommandOutput}
	defer func() { record.Stdout = stdout.String(); record.Stderr = stderr.String() }()
	marker, err := randomToken(24)
	if err != nil {
		return "", -1, err
	}
	frames := make(chan shellFrame, 2)
	if err = p.stdout.begin(marker, stdout, frames); err == nil {
		err = p.stderr.begin(marker, stderr, frames)
	}
	if err != nil {
		p.close("transcript persistence failed")
		return "", -1, err
	}
	script := "eval '" + strings.ReplaceAll(record.Command, "'", "'\\''") + "'\n__sshhub_status=$?\nprintf '\\036" + marker + ":%s\\037' \"$__sshhub_status\"\nprintf '\\036" + marker + ":%s\\037' \"$__sshhub_status\" >&2\n"
	wrote := make(chan error, 1)
	go func() { _, err := io.WriteString(p.stdin, script); wrote <- err }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	seen := 0
	exit := -1
	for {
		select {
		case err := <-wrote:
			if err != nil {
				p.close("shell input failed")
				return combineCommandOutput(stdout.String(), stderr.String()), -1, err
			}
		case frame := <-frames:
			seen++
			if frame.stream == "stdout" {
				exit = frame.status
			}
			if seen == 2 {
				return combineCommandOutput(stdout.String(), stderr.String()), exit, nil
			}
		case <-ctx.Done():
			p.close("command cancelled or timed out; shell state lost")
			return combineCommandOutput(stdout.String(), stderr.String()), 124, ctx.Err()
		case <-p.done:
			return combineCommandOutput(stdout.String(), stderr.String()), -1, errors.New("persistent shell disconnected; command outcome may be unknown")
		case <-ticker.C:
			snapshot := *record
			snapshot.Stdout = stdout.String()
			snapshot.Stderr = stderr.String()
			snapshot.Output = combineCommandOutput(snapshot.Stdout, snapshot.Stderr)
			a.auditMu.Lock()
			err := a.saveAuditLocked(snapshot)
			a.auditMu.Unlock()
			if err != nil {
				p.close("audit persistence failed")
				return snapshot.Output, -1, err
			}
		}
	}
}
func (a *App) listConnections(clientID string) []ConnectionInfo {
	a.connectionsMu.Lock()
	defer a.connectionsMu.Unlock()
	out := []ConnectionInfo{}
	for _, p := range a.connections {
		info := p.snapshot()
		if clientID == "" || info.ClientID == clientID {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}
func (a *App) checkConnection(ctx context.Context, p *persistentConnection) ConnectionInfo {
	if !p.checkMu.TryLock() {
		return p.snapshot()
	}
	defer p.checkMu.Unlock()
	info := p.snapshot()
	if info.Status != "open" && info.Status != "busy" {
		return info
	}
	_, h, _, err := a.resolveExecution(info.ClientID, info.HostID)
	if err != nil || h != p.host {
		p.close("host access revoked or configuration changed")
		return p.snapshot()
	}
	if info.Status == "open" && a.sessionIdleTimeout > 0 && time.Since(info.LastUsedAt) > a.sessionIdleTimeout {
		p.close("idle timeout")
		return p.snapshot()
	}
	done := make(chan error, 1)
	go func() { _, _, err := p.client.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err = <-done:
	case <-timer.C:
		err = errors.New("SSH keepalive timed out")
	case <-ctx.Done():
		err = ctx.Err()
	}
	p.mu.Lock()
	p.info.CheckedAt = time.Now().UTC()
	p.mu.Unlock()
	if err != nil {
		p.close(err.Error())
	}
	return p.snapshot()
}
func (a *App) checkConnections(ctx context.Context) {
	a.connectionsMu.Lock()
	all := []*persistentConnection{}
	for _, p := range a.connections {
		all = append(all, p)
	}
	a.connectionsMu.Unlock()
	var wg sync.WaitGroup
	for _, p := range all {
		wg.Add(1)
		go func(p *persistentConnection) { defer wg.Done(); a.checkConnection(ctx, p) }(p)
	}
	wg.Wait()
}
func (a *App) closeAllConnections(reason string) {
	a.connectionsMu.Lock()
	defer a.connectionsMu.Unlock()
	for _, p := range a.connections {
		if s := p.snapshot().Status; s == "open" || s == "busy" {
			p.close(reason)
		}
	}
}
func (a *App) handleConnections(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	writeJSON(w, 200, a.listConnections(""))
}
func (a *App) handleConnectionCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	p, err := a.connection("", r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, a.checkConnection(r.Context(), p))
}
func (a *App) handleConnectionClose(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	p, err := a.connection("", r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if s := p.snapshot().Status; s == "open" || s == "busy" {
		p.close("closed by administrator")
	}
	writeJSON(w, 200, p.snapshot())
}

func connectionToolResult(value any, err error) map[string]any {
	if err != nil {
		return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}
	}
	encoded, _ := json.Marshal(value)
	return map[string]any{"content": []map[string]string{{"type": "text", "text": string(encoded)}}, "structuredContent": map[string]any{"result": value}}
}

// Run immediately after administrative permission changes, without sending traffic.
func (a *App) enforceConnectionPolicies() {
	a.connectionsMu.Lock()
	all := []*persistentConnection{}
	for _, p := range a.connections {
		all = append(all, p)
	}
	a.connectionsMu.Unlock()
	for _, p := range all {
		info := p.snapshot()
		if info.Status != "open" && info.Status != "busy" {
			continue
		}
		_, host, _, err := a.resolveExecution(info.ClientID, info.HostID)
		if err != nil || host != p.host {
			p.close("host access revoked or configuration changed")
		}
	}
}

func (a *App) recordConnectionClose(info ConnectionInfo, host Host, clientName, reason string) {
	id, err := a.store.resourceID("run")
	if err != nil {
		log.Printf("session close audit ID: %v", err)
		return
	}
	now := time.Now().UTC()
	record := AuditSession{ID: id, Operation: "close", ConnectionID: info.ID, ClientID: info.ClientID, ClientName: clientName, HostID: info.HostID, Host: host, Command: "[close persistent shell]", Status: "completed", CreatedAt: now, FinishedAt: now, Output: reason, ExitCode: 0}
	a.auditMu.Lock()
	err = a.saveAuditLocked(record)
	a.auditMu.Unlock()
	if err != nil {
		log.Printf("session close audit persistence failed: %v", err)
	}
}
