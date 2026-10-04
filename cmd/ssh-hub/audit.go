package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type clientContextKey struct{}

// Migrate legacy clients once: keep their existing hosts, require confirmation,
// and never grant subsequently added hosts automatically.
func migrateClientPolicies(store *Store) error {
	return store.update(func(state *State) error {
		ids := make([]string, 0, len(state.Hosts))
		for id := range state.Hosts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for id, client := range state.Clients {
			changed := false
			if !client.HostAccessConfigured {
				client.HostAccessConfigured, client.RequireApproval = true, true
				client.AllowedHostIDs = append([]string{}, ids...)
				changed = true
			}
			if !client.FeatureAccessConfigured {
				client.FeatureAccessConfigured = true
				client.HostFeatures = make(map[string][]string, len(client.AllowedHostIDs))
				for _, hostID := range client.AllowedHostIDs {
					client.HostFeatures[hostID] = []string{"exec", "shell", "agent"}
				}
				changed = true
			}
			if changed {
				state.Clients[id] = client
			}
		}
		return nil
	})
}

func clientIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(clientContextKey{}).(string)
	return id
}
func clientAllowsHost(client OAuthClient, hostID string) bool {
	return client.HostAccessConfigured && hasValue(client.AllowedHostIDs, hostID)
}

func clientAllowsFeature(client OAuthClient, hostID, feature string) bool {
	if !clientAllowsHost(client, hostID) {
		return false
	}
	if !client.FeatureAccessConfigured {
		return true // Existing in-memory/legacy clients retain their host grants.
	}
	return hasValue(client.HostFeatures[hostID], feature)
}

func clientHasAnyFeature(client OAuthClient, hostID string) bool {
	return clientAllowsFeature(client, hostID, "exec") || clientAllowsFeature(client, hostID, "shell") || clientAllowsFeature(client, hostID, "agent")
}

type AuditSession struct {
	Operation      string    `json:"operation,omitempty"`
	ConnectionID   string    `json:"connectionId,omitempty"`
	ID             string    `json:"id"`
	ClientID       string    `json:"clientId"`
	ClientName     string    `json:"clientName"`
	HostID         string    `json:"hostId"`
	Host           Host      `json:"host"`
	Command        string    `json:"command"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt,omitempty"`
	StartedAt      time.Time `json:"startedAt,omitempty"`
	FinishedAt     time.Time `json:"finishedAt,omitempty"`
	Decision       string    `json:"decision,omitempty"`
	DecidedAt      time.Time `json:"decidedAt,omitempty"`
	DecidedBy      string    `json:"decidedBy,omitempty"`
	Stdout         string    `json:"stdout,omitempty"`
	Stderr         string    `json:"stderr,omitempty"`
	Output         string    `json:"output,omitempty"`
	ExitCode       int       `json:"exitCode"`
	Error          string    `json:"error,omitempty"`
}

var auditIDPattern = regexp.MustCompile(`^(run-[1-9][0-9]*|[0-9]{8}T[0-9]{6}_[A-Za-z0-9_-]{16})$`)

func (a *App) auditDir() string { return filepath.Join(filepath.Dir(a.store.path), "audit") }

// Callers hold auditMu. Write the record before allowing any SSH connection.
func (a *App) saveAuditLocked(record AuditSession) error {
	if !auditIDPattern.MatchString(record.ID) {
		return errors.New("invalid session id")
	}
	if err := os.MkdirAll(a.auditDir(), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(a.auditDir(), ".audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(a.auditDir(), record.ID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(a.auditDir())
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (a *App) readAuditLocked(id string) (AuditSession, error) {
	var record AuditSession
	if !auditIDPattern.MatchString(id) {
		return record, errors.New("session not found")
	}
	data, err := os.ReadFile(filepath.Join(a.auditDir(), id+".json"))
	if err != nil {
		return record, errors.New("session not found")
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if record.Status == "pending" && time.Now().After(record.ExpiresAt) {
		record.Status, record.Error, record.FinishedAt = "expired", "Approval expired; no connection was made", time.Now().UTC()
		if err := a.saveAuditLocked(record); err != nil {
			return record, err
		}
	}
	return record, nil
}

func (a *App) recoverAuditSessions() error {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	entries, err := os.ReadDir(a.auditDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := a.readAuditLocked(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		if record.Status == "pending" || record.Status == "running" {
			record.Status, record.Error, record.FinishedAt = "interrupted", "Service restarted; execution will not be replayed. A previously running remote command may have continued.", time.Now().UTC()
			if err := a.saveAuditLocked(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) resolveExecution(clientID, hostID, feature string) (OAuthClient, Host, StoredKey, error) {
	var client OAuthClient
	var host Host
	var key StoredKey
	err := a.store.view(func(state State) error {
		var ok bool
		client, ok = state.Clients[clientID]
		if !ok || !clientAllowsHost(client, hostID) {
			return errors.New("client is not allowed to access this host")
		}
		if !clientAllowsFeature(client, hostID, feature) {
			return fmt.Errorf("client is not allowed to use %s on this host", feature)
		}
		host, ok = state.Hosts[hostID]
		if !ok {
			return errors.New("host not found or no longer available")
		}
		key, ok = state.Keys[host.KeyID]
		if !ok {
			return errors.New("SSH key not found")
		}
		return nil
	})
	return client, host, key, err
}

func (a *App) submitExecution(ctx context.Context, hostID, command string, timeout int) (AuditSession, error) {
	return a.submitOperation(ctx, hostID, command, timeout, "exec", "")
}

func (a *App) submitOperation(ctx context.Context, hostID, command string, timeout int, operation, connectionID string) (AuditSession, error) {
	if operation == "open" {
		var err error
		connectionID, err = a.store.resourceID("shell")
		if err != nil {
			return AuditSession{}, err
		}
	}
	if connectionID != "" && operation != "open" {
		p, err := a.connection(clientIDFromContext(ctx), connectionID)
		if err != nil {
			return AuditSession{}, err
		}
		if p.snapshot().HostID != hostID {
			return AuditSession{}, errors.New("session belongs to another host")
		}
	}
	if timeout < 0 || timeout > 300 {
		return AuditSession{}, errors.New("timeout_seconds must be between 1 and 300 when specified")
	}
	id, err := a.store.resourceID("run")
	if err != nil {
		return AuditSession{}, err
	}
	now := time.Now().UTC()
	record := AuditSession{Operation: operation, ConnectionID: connectionID, ID: id, ClientID: clientIDFromContext(ctx), HostID: hostID, Command: command, TimeoutSeconds: timeout, CreatedAt: now, ExitCode: -1}
	feature := operationFeature(operation, connectionID)
	client, host, _, accessErr := a.resolveExecution(record.ClientID, hostID, feature)
	record.ClientName = client.Name
	if accessErr != nil {
		record.Status, record.Error, record.FinishedAt = "denied", accessErr.Error(), now
	} else {
		record.Host = host
		if client.RequireApproval {
			record.Status, record.ExpiresAt = "pending", now.Add(10*time.Minute)
		} else {
			record.Status = "running"
			record.StartedAt = now
		}
	}
	a.auditMu.Lock()
	err = a.saveAuditLocked(record)
	a.auditMu.Unlock()
	if err != nil {
		return AuditSession{}, errors.New("cannot persist audit record; execution refused")
	}
	if record.Status == "running" {
		record = a.executeAudited(ctx, record)
	}
	return record, nil
}

func operationFeature(operation, connectionID string) string {
	switch {
	case operation == "agent":
		return "agent"
	case operation == "open" || connectionID != "":
		return "shell"
	default:
		return "exec"
	}
}

func (a *App) executeAudited(ctx context.Context, record AuditSession) AuditSession {
	_, host, key, err := a.resolveExecution(record.ClientID, record.HostID, operationFeature(record.Operation, record.ConnectionID))
	if err == nil && host != record.Host {
		err = errors.New("host configuration changed; submit a new request")
	}
	if err == nil {
		switch {
		case record.Operation == "agent":
			record.Output, record.ExitCode, err = a.runAgentOperation(ctx, host, key, &record)
		case record.Operation == "open":
			err = a.openPersistent(ctx, host, key, &record)
			record.ExitCode = 0
		case record.ConnectionID != "":
			record.Output, record.ExitCode, err = a.runPersistent(ctx, host, &record)
		default:
			record.Output, record.ExitCode, err = a.runSSHCommand(ctx, host, key, record.Command, record.TimeoutSeconds, &record)
		}
	}
	record.FinishedAt = time.Now().UTC()
	record.Status = "completed"
	if err != nil {
		record.Status, record.Error = "failed", err.Error()
		if record.ExitCode == 0 {
			record.ExitCode = -1
		}
	} else if record.ExitCode != 0 {
		record.Status = "failed"
	}
	a.auditMu.Lock()
	saveErr := a.saveAuditLocked(record)
	a.auditMu.Unlock()
	if saveErr != nil {
		if record.ConnectionID != "" {
			if p, e := a.connection(record.ClientID, record.ConnectionID); e == nil && p.snapshot().Status != "connecting" {
				p.close("audit completion persistence failed")
			}
		}
		log.Printf("audit completion write failed for session %s: %v", record.ID, saveErr)
		record.Status, record.Error = "failed", "Execution finished but audit persistence failed; inspect server storage before retrying"
	}
	return record
}

func auditToolResult(record AuditSession) map[string]any {
	text := fmt.Sprintf("session_id: %s\nstatus: %s\nexit_code: %d\n%s", record.ID, record.Status, record.ExitCode, record.Output)
	if record.ConnectionID != "" {
		text += "\nconnection_id: " + record.ConnectionID
	}
	if record.Status == "pending" {
		text += "\nAdministrator approval is required in SSH Hub. No SSH connection has been made. Poll ssh_session_status with this session_id; do not resubmit the command."
	}
	if record.Error != "" {
		text += "\n" + record.Error
	}
	structured := map[string]any{"connection_id": record.ConnectionID, "operation": record.Operation, "session_id": record.ID, "status": record.Status, "exit_code": record.ExitCode, "output": record.Output, "stdout": record.Stdout, "stderr": record.Stderr, "error": record.Error}
	if record.Status == "pending" || record.Status == "running" {
		next := map[string]any{"name": "ssh_session_status", "arguments": map[string]string{"session_id": record.ID}}
		structured["next_call"] = next
		encoded, _ := json.Marshal(next)
		text += "\nnext_call: " + string(encoded)
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "structuredContent": structured, "isError": record.Status != "completed" && record.Status != "pending" && record.Status != "running"}
}

func (a *App) clientAudit(ctx context.Context, id string) (AuditSession, error) {
	a.auditMu.Lock()
	record, err := a.readAuditLocked(id)
	if err != nil || record.ClientID != clientIDFromContext(ctx) {
		a.auditMu.Unlock()
		return AuditSession{}, errors.New("session not found")
	}
	a.auditMu.Unlock()
	var allowed bool
	_ = a.store.view(func(state State) error {
		allowed = clientAllowsFeature(state.Clients[record.ClientID], record.HostID, operationFeature(record.Operation, record.ConnectionID))
		return nil
	})
	if !allowed {
		return AuditSession{}, errors.New("session not found")
	}
	return record, nil
}

func (a *App) handleClientPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var input struct {
		AllowedHostIDs  []string            `json:"allowedHostIds"`
		HostFeatures    map[string][]string `json:"hostFeatures"`
		RequireApproval bool                `json:"requireApproval"`
	}
	if decodeJSON(r, &input) != nil {
		writeJSON(w, 400, map[string]string{"error": "无效的权限设置"})
		return
	}
	err := a.store.update(func(state *State) error {
		client, ok := state.Clients[r.PathValue("id")]
		if !ok {
			return errors.New("客户端不存在")
		}
		features := input.HostFeatures
		if features == nil { // Accept older consoles/API clients; preserve their grants.
			features = make(map[string][]string, len(input.AllowedHostIDs))
			for _, id := range input.AllowedHostIDs {
				features[id] = []string{"exec", "shell", "agent"}
			}
		}
		allowed := make([]string, 0, len(features))
		for id, selected := range features {
			if _, ok := state.Hosts[id]; !ok {
				return errors.New("机器不存在")
			}
			seen := map[string]bool{}
			for _, feature := range selected {
				if feature != "exec" && feature != "shell" && feature != "agent" || seen[feature] {
					return errors.New("无效的功能权限")
				}
				seen[feature] = true
			}
			if len(selected) > 0 {
				allowed = append(allowed, id)
			}
		}
		sort.Strings(allowed)
		client.HostAccessConfigured, client.AllowedHostIDs, client.RequireApproval = true, allowed, input.RequireApproval
		client.FeatureAccessConfigured, client.HostFeatures = true, features
		state.Clients[client.ID] = client
		return nil
	})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	a.enforceConnectionPolicies()
	w.WriteHeader(204)
}

func (a *App) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	all, err := a.sortedAuditsLocked(r.URL.Query().Get("before"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	records := []AuditSession{}
	for _, record := range all {
		if status := r.URL.Query().Get("status"); status != "" && record.Status != status {
			continue
		}
		record.Stdout, record.Stderr, record.Output = "", "", ""
		records = append(records, record)
		if len(records) == 100 {
			break
		}
	}
	writeJSON(w, 200, records)
}

func (a *App) handleAuditGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	record, err := a.readAuditLocked(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, record)
}

func (a *App) decideAudit(id, decision, actor string) (AuditSession, error) {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	record, err := a.readAuditLocked(id)
	if err != nil {
		return record, err
	}
	if record.Status != "pending" {
		return record, errors.New("请求已处理或已过期")
	}
	if decision != "approve" && decision != "deny" {
		return record, errors.New("无效的审批操作")
	}
	record.Decision, record.DecidedAt, record.DecidedBy = decision, time.Now().UTC(), actor
	if decision == "deny" {
		record.Status, record.FinishedAt = "rejected", record.DecidedAt
	} else {
		_, host, _, err := a.resolveExecution(record.ClientID, record.HostID, operationFeature(record.Operation, record.ConnectionID))
		if err != nil || host != record.Host {
			record.Status, record.Error, record.FinishedAt = "denied", "Permissions or host configuration changed; no connection was made", record.DecidedAt
		} else {
			record.Status, record.StartedAt = "running", record.DecidedAt
		}
	}
	return record, a.saveAuditLocked(record)
}

func (a *App) handleAuditDecision(w http.ResponseWriter, r *http.Request) {
	session, ok := a.checkCSRF(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var input struct {
		Decision string `json:"decision"`
	}
	if decodeJSON(r, &input) != nil {
		writeJSON(w, 400, map[string]string{"error": "无效请求"})
		return
	}
	record, err := a.decideAudit(r.PathValue("id"), input.Decision, session.Actor)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	if record.Status == "running" {
		go a.executeAudited(context.Background(), record)
	}
	writeJSON(w, 200, record)
}

// Order by creation time, not filename: legacy and short IDs coexist. The ID
// breaks ties so a cursor never skips records with the same timestamp.
func (a *App) sortedAuditsLocked(before string) ([]AuditSession, error) {
	var cursor AuditSession
	if before != "" {
		var err error
		cursor, err = a.readAuditLocked(before)
		if err != nil {
			return nil, errors.New("invalid audit cursor")
		}
	}
	entries, err := os.ReadDir(a.auditDir())
	if os.IsNotExist(err) {
		return []AuditSession{}, nil
	}
	if err != nil {
		return nil, err
	}
	records := []AuditSession{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !auditIDPattern.MatchString(id) {
			continue
		}
		record, err := a.readAuditLocked(id)
		if err != nil {
			return nil, err
		}
		if before != "" && (record.CreatedAt.After(cursor.CreatedAt) || (record.CreatedAt.Equal(cursor.CreatedAt) && record.ID >= cursor.ID)) {
			continue
		}
		record.Stdout, record.Stderr, record.Output = "", "", ""
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].ID > records[j].ID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
	return records, nil
}
