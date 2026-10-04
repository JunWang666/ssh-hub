package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func persistentTools() []map[string]any {
	str := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	tool := func(name, description string, read bool, props map[string]any, required ...string) map[string]any {
		if required == nil {
			required = []string{}
		}
		return map[string]any{"name": name, "description": description, "annotations": map[string]any{"readOnlyHint": read, "destructiveHint": !read, "openWorldHint": true}, "inputSchema": map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}}
	}
	return []map[string]any{
		tool("ssh_open_session", "Open a persistent non-interactive POSIX sh on a permitted host, subject to admin approval. Poll ssh_session_status using session_id until completed, then use connection_id with ssh_exec. Preserves cwd, variables and background processes until closed/disconnected; no automatic reconnect. Idle timeout defaults to 24 hours (administrator configurable).", false, map[string]any{"host_id": str("Host ID or unique name from ssh_list_hosts")}, "host_id"),
		tool("ssh_list_sessions", "List only this client's persistent shells and their last known status.", true, map[string]any{}),
		tool("ssh_check_session", "Manually probe this client's existing SSH transport. Does not reconnect or execute a command.", true, map[string]any{"connection_id": str("Persistent shell ID")}, "connection_id"),
		tool("ssh_close_session", "Close this client's persistent shell. Running and background tasks may terminate; command results can become unknown.", false, map[string]any{"connection_id": str("Persistent shell ID")}, "connection_id"),
		tool("ssh_read_session", "Read a paginated persisted session transcript, including background stdout/stderr between commands. Only the owning client may read it, including after service restart.", true, map[string]any{"connection_id": str("Persistent shell ID"), "offset": map[string]any{"type": "integer", "minimum": 0}}, "connection_id"),
		tool("ssh_audit_list", "List this client's audit summaries, newest first, at most 50 per page. Use next_before to paginate and ssh_audit_read for command output.", true, map[string]any{"before": str("Pagination cursor from next_before"), "connection_id": str("Optional persistent session filter"), "status": str("Optional execution status filter")}),
		tool("ssh_audit_read", "Read this client's complete command audit record, approval, stdout, stderr and exit code.", true, map[string]any{"session_id": str("Audit execution ID")}, "session_id"),
	}
}
func (a *App) callPersistentTool(name string, raw json.RawMessage, ctx context.Context) (any, *jsonRPCError) {
	var args struct {
		HostID       string `json:"host_id"`
		ConnectionID string `json:"connection_id"`
		SessionID    string `json:"session_id"`
		Before       string `json:"before"`
		Status       string `json:"status"`
		Offset       int64  `json:"offset"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &args) != nil {
		return nil, &jsonRPCError{Code: -32602, Message: "Invalid arguments"}
	}
	client := clientIDFromContext(ctx)
	if client == "" {
		return connectionToolResult(nil, errors.New("client authentication required")), nil
	}
	switch name {
	case "ssh_open_session":
		if args.HostID == "" {
			return nil, &jsonRPCError{Code: -32602, Message: "host_id required"}
		}
		hostID, err := a.resolveHostReference(ctx, args.HostID)
		if err != nil {
			return connectionToolResult(nil, err), nil
		}
		record, err := a.submitOperation(ctx, hostID, "[open persistent shell]", 0, "open", "")
		if err != nil {
			return connectionToolResult(nil, err), nil
		}
		return auditToolResult(record), nil
	case "ssh_list_sessions":
		return connectionToolResult(a.listConnections(client), nil), nil
	case "ssh_audit_list":
		records, next, err := a.clientAuditList(client, args.Before, args.ConnectionID, args.Status)
		return connectionToolResult(map[string]any{"records": records, "next_before": next}, err), nil
	case "ssh_audit_read":
		record, err := a.clientAudit(ctx, args.SessionID)
		return connectionToolResult(record, err), nil
	case "ssh_read_session":
		result, err := a.readTranscript(client, args.ConnectionID, args.Offset)
		return connectionToolResult(result, err), nil
	default:
		p, err := a.connection(client, args.ConnectionID)
		if err != nil {
			return connectionToolResult(nil, err), nil
		}
		if _, _, _, err := a.resolveExecution(client, p.snapshot().HostID, "shell"); err != nil {
			return connectionToolResult(nil, err), nil
		}
		if name == "ssh_check_session" {
			return connectionToolResult(a.checkConnection(ctx, p), nil), nil
		}
		if s := p.snapshot().Status; s == "open" || s == "busy" {
			p.close("closed by owning client")
		}
		return connectionToolResult(p.snapshot(), nil), nil
	}
}
func (a *App) clientAuditList(client, before, connection, status string) ([]AuditSession, string, error) {
	var policy OAuthClient
	_ = a.store.view(func(state State) error { policy = state.Clients[client]; return nil })
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	records := []AuditSession{}
	if before != "" && !auditIDPattern.MatchString(before) {
		return records, "", errors.New("invalid cursor")
	}
	if before != "" {
		cursor, err := a.readAuditLocked(before)
		if err != nil || cursor.ClientID != client {
			return nil, "", errors.New("invalid audit cursor")
		}
	}
	all, err := a.sortedAuditsLocked(before)
	if err != nil {
		return nil, "", err
	}
	for _, record := range all {
		if record.ClientID != client || (connection != "" && record.ConnectionID != connection) || (status != "" && record.Status != status) {
			continue
		}
		if !clientAllowsFeature(policy, record.HostID, operationFeature(record.Operation, record.ConnectionID)) {
			continue
		}
		if len(records) == 50 {
			return records, records[len(records)-1].ID, nil
		}
		record.Stdout = ""
		record.Stderr = ""
		record.Output = ""
		records = append(records, record)
	}
	return records, "", nil
}

var connectionIDPattern = regexp.MustCompile(`^(shell-[1-9][0-9]*|[A-Za-z0-9_-]{32})$`)

func (a *App) readTranscript(client, id string, offset int64) (map[string]any, error) {
	if !connectionIDPattern.MatchString(id) || offset < 0 {
		return nil, errors.New("invalid session or offset")
	}
	// Persist ownership via the immutable open audit. This also supports reading after restart.
	a.auditMu.Lock()
	entries, err := os.ReadDir(a.auditDir())
	owned := false
	ownedHost := ""
	if err == nil {
		for _, e := range entries {
			auditID := strings.TrimSuffix(e.Name(), ".json")
			if !auditIDPattern.MatchString(auditID) {
				continue
			}
			r, e := a.readAuditLocked(auditID)
			if e == nil && r.ConnectionID == id && r.Operation == "open" && (client == "" || r.ClientID == client) {
				owned = true
				ownedHost = r.HostID
				break
			}
		}
	}
	a.auditMu.Unlock()
	if !owned {
		return nil, errors.New("persistent session not found")
	}
	if client != "" {
		if _, _, _, err := a.resolveExecution(client, ownedHost, "shell"); err != nil {
			return nil, errors.New("persistent session not found")
		}
	}
	f, err := os.Open(filepath.Join(filepath.Dir(a.store.path), "transcripts", id+".jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if offset > stat.Size() {
		return nil, errors.New("offset exceeds transcript size")
	}

	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(f)
	var data []byte
	entriesOut := []json.RawMessage{}
	for len(data) < 64*1024 {
		line, readErr := reader.ReadBytes('\n')
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		if !json.Valid(line) {
			return nil, errors.New("invalid transcript offset or record")
		}
		data = append(data, line...)
		entriesOut = append(entriesOut, json.RawMessage(line))
	}
	next := offset + int64(len(data))
	return map[string]any{"connection_id": id, "offset": offset, "next_offset": next, "has_more": next < stat.Size(), "data": string(data), "entries": entriesOut}, nil
}
func (a *App) handleTranscript(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	offset := int64(0)
	if raw := r.URL.Query().Get("offset"); raw != "" {
		var err error
		offset, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid offset"})
			return
		}
	}
	result, err := a.readTranscript("", r.PathValue("id"), offset)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}
