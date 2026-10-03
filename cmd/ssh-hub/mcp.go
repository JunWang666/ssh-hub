package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxMCPBody        = 1024 * 1024
	maxCommandBytes   = 16 * 1024
	maxCommandOutput  = 512 * 1024
	defaultMCPVersion = "2025-11-25"
	legacyMCPVersion  = "2025-03-26"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !a.validMCPOrigin(origin, r.Host) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	token, ok := a.validBearerToken(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope="mcp"`, a.publicURL+"/.well-known/oauth-protected-resource"))
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, token.ClientID))
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" && !strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/event-stream") && accept != "*/*" {
		http.Error(w, "Accept must allow application/json or text/event-stream", http.StatusNotAcceptable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMCPBody)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body is invalid or too large", http.StatusBadRequest)
		return
	}
	var request jsonRPCRequest
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] == '[' {
		a.writeRPCError(w, json.RawMessage("null"), -32600, "Invalid Request")
		return
	}
	if err := json.Unmarshal(data, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
		a.writeRPCError(w, request.ID, -32600, "Invalid Request")
		return
	}
	protocolVersion := r.Header.Get("MCP-Protocol-Version")
	if request.Method == "initialize" {
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(request.Params, &initParams)
		protocolVersion = supportedProtocolVersion(initParams.ProtocolVersion)
	} else {
		if protocolVersion == "" {
			protocolVersion = legacyMCPVersion
		} else if !isSupportedProtocolVersion(protocolVersion) {
			http.Error(w, "unsupported MCP-Protocol-Version", http.StatusBadRequest)
			return
		}
	}
	if len(request.ID) == 0 {
		if strings.HasPrefix(request.Method, "notifications/") || strings.HasPrefix(request.Method, "notifications.") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		a.writeRPCError(w, json.RawMessage("null"), -32600, "Requests must include an id")
		return
	}
	if !validRPCID(request.ID) {
		a.writeRPCError(w, json.RawMessage("null"), -32600, "Invalid request id")
		return
	}
	result, rpcErr := a.dispatchMCP(request.Method, request.Params, r.Context())
	if rpcErr != nil {
		a.writeRPCError(w, request.ID, rpcErr.Code, rpcErr.Message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("MCP-Protocol-Version", protocolVersion)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(jsonRPCResponse{JSONRPC: "2.0", ID: request.ID, Result: result})
}

func (a *App) validMCPOrigin(origin, requestHost string) bool {
	return a.validSameOrigin(origin, requestHost)
}

func (a *App) validBearerToken(header string) (AccessToken, bool) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || strings.ContainsAny(parts[1], " \t\r\n") {
		return AccessToken{}, false
	}
	var token AccessToken
	err := a.store.view(func(state State) error {
		token = state.Tokens[tokenDigest(parts[1])]
		return nil
	})
	if err != nil || token.ClientID == "" || time.Now().After(token.ExpiresAt) || token.Scope != "mcp" || !a.resourceIsValid(token.Resource) {
		return AccessToken{}, false
	}
	return token, true
}

func (a *App) writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &jsonRPCError{Code: code, Message: message}})
}

func validRPCID(raw json.RawMessage) bool {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func (a *App) dispatchMCP(method string, params json.RawMessage, ctx context.Context) (any, *jsonRPCError) {
	switch method {
	case "initialize":
		var input struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &input)
		version := input.ProtocolVersion
		version = supportedProtocolVersion(version)
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "ssh-hub", "version": "0.3.0"},
			"instructions":    "Use ssh_list_hosts to see permitted hosts. Use ssh_open_session then ssh_exec with connection_id for a persistent shell. ssh_audit_list and ssh_audit_read expose only your audit records. ssh_exec may return a pending approval session; use ssh_session_status to poll it instead of resubmitting the command.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefinitions()}, nil
	case "tools/call":
		return a.callTool(params, ctx)
	default:
		return nil, &jsonRPCError{Code: -32601, Message: "Method not found"}
	}
}

func isSupportedProtocolVersion(version string) bool {
	switch version {
	case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
		return true
	default:
		return false
	}
}

func supportedProtocolVersion(version string) string {
	if isSupportedProtocolVersion(version) {
		return version
	}
	return defaultMCPVersion
}

func toolDefinitions() []map[string]any {
	return append(persistentTools(), []map[string]any{
		{"name": "ssh_session_status", "description": "Read your SSH session status and recorded output. After admin approval, poll a pending session here; do not resubmit ssh_exec.", "annotations": map[string]any{"readOnlyHint": true}, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"session_id": map[string]any{"type": "string"}}, "required": []string{"session_id"}, "additionalProperties": false}},
		{
			"name":        "ssh_list_hosts",
			"annotations": map[string]any{"readOnlyHint": true},
			"description": "List the SSH hosts configured by the administrator.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		},
		{
			"name":        "ssh_exec",
			"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
			"description": "Run a shell command on an allowed SSH host. If approval is required, returns a pending session ID without connecting; poll ssh_session_status after administrator approval. Supply connection_id from ssh_open_session to preserve shell state across commands; omit it for an independent execution.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"connection_id":   map[string]any{"type": "string", "description": "Optional persistent shell ID from ssh_open_session."},
					"host_id":         map[string]any{"type": "string", "description": "Host id returned by ssh_list_hosts."},
					"command":         map[string]any{"type": "string", "description": "Remote shell command to run."},
					"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 300, "description": "Optional timeout, capped by the host setting."},
				},
				"required":             []string{"host_id", "command"},
				"additionalProperties": false,
			},
		},
	}...)
}

func (a *App) callTool(params json.RawMessage, ctx context.Context) (any, *jsonRPCError) {
	var input struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &input); err != nil || input.Name == "" {
		return nil, &jsonRPCError{Code: -32602, Message: "Invalid params: name is required"}
	}
	switch input.Name {
	case "ssh_list_hosts":
		var hosts []publicHost
		_ = a.store.view(func(state State) error {
			client, ok := state.Clients[clientIDFromContext(ctx)]
			if !ok {
				return nil
			}
			for _, host := range state.Hosts {
				if !clientAllowsHost(client, host.ID) {
					continue
				}
				hosts = append(hosts, publicHost{
					ID: host.ID, Name: host.Name, Address: host.Address, Username: host.Username,
					KeyID: host.KeyID, KeyName: state.Keys[host.KeyID].Name,
					HostKeyFingerprint: host.HostKeyFingerprint, TimeoutSeconds: host.TimeoutSeconds,
					CreatedAt: host.CreatedAt,
				})
			}
			return nil
		})
		if hosts == nil {
			hosts = []publicHost{}
		}
		return map[string]any{"content": []map[string]string{{"type": "text", "text": formatHostList(hosts)}}, "structuredContent": map[string]any{"hosts": hosts}}, nil
	case "ssh_session_status":
		var args struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(input.Arguments, &args) != nil || args.SessionID == "" {
			return nil, &jsonRPCError{Code: -32602, Message: "session_id is required"}
		}
		record, err := a.clientAudit(ctx, args.SessionID)
		if err != nil {
			return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}, nil
		}
		return auditToolResult(record), nil
	case "ssh_open_session", "ssh_list_sessions", "ssh_check_session", "ssh_close_session", "ssh_audit_list", "ssh_audit_read", "ssh_read_session":
		return a.callPersistentTool(input.Name, input.Arguments, ctx)
	case "ssh_exec":
		var args struct {
			ConnectionID   string `json:"connection_id"`
			HostID         string `json:"host_id"`
			Command        string `json:"command"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}
		if err := json.Unmarshal(input.Arguments, &args); err != nil || args.HostID == "" || strings.TrimSpace(args.Command) == "" || len(args.Command) > maxCommandBytes {
			return nil, &jsonRPCError{Code: -32602, Message: "Invalid params: host_id and command are required; command must be at most 16 KiB"}
		}
		record, err := a.submitOperation(ctx, args.HostID, args.Command, args.TimeoutSeconds, "exec", args.ConnectionID)
		if record.ID != "" {
			return auditToolResult(record), nil
		}
		if err == nil {
			err = errors.New("execution could not be created")
		}
		return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}, nil
	default:
		return nil, &jsonRPCError{Code: -32602, Message: "Unknown tool"}
	}
}

func formatHostList(hosts []publicHost) string {
	if len(hosts) == 0 {
		return "No SSH hosts are available to this client. Ask the administrator to grant host access in the SSH Hub web UI."
	}
	var builder strings.Builder
	for _, host := range hosts {
		fmt.Fprintf(&builder, "- id: %s | name: %s | address: %s | user: %s | key: %s\n", host.ID, host.Name, host.Address, host.Username, host.KeyName)
	}
	return strings.TrimSpace(builder.String())
}

type outputBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *outputBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			_, _ = b.buffer.Write(value[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buffer.Write(value)
		}
	} else if len(value) > 0 {
		b.truncated = true
	}
	return len(value), nil
}

func (b *outputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	value := b.buffer.String()
	if b.truncated {
		value += "\n[output truncated at 512 KiB]"
	}
	return value
}

type keyMaterial struct {
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`
}

func (a *App) runSSHCommand(parent context.Context, host Host, key StoredKey, command string, requestedTimeout int, record *AuditSession) (string, int, error) {
	signer, err := a.keySigner(key)
	if err != nil {
		return "", 0, errors.New("could not load the configured SSH key: " + err.Error())
	}

	timeout := host.TimeoutSeconds
	if requestedTimeout > 0 && requestedTimeout < timeout {
		timeout = requestedTimeout
	}
	if timeout < 1 || timeout > 300 {
		timeout = 30
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: time.Duration(timeout) * time.Second}).DialContext(ctx, "tcp", host.Address)
	if err != nil {
		return "", 0, fmt.Errorf("connect to %s: %w", host.Address, err)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = connection.SetDeadline(deadline)
	}
	config := &ssh.ClientConfig{
		User: host.Username,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(actual), []byte(host.HostKeyFingerprint)) != 1 {
				return errors.New("SSH server host key fingerprint does not match the configured fingerprint")
			}
			return nil
		},
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, host.Address, config)
	if err != nil {
		_ = connection.Close()
		if ctx.Err() != nil {
			return "", 0, fmt.Errorf("SSH connection timed out after %d seconds", timeout)
		}
		return "", 0, fmt.Errorf("SSH handshake or authentication failed: %w", err)
	}
	_ = connection.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()
	stdout := &outputBuffer{limit: maxCommandOutput}
	stderr := &outputBuffer{limit: maxCommandOutput}
	session.Stdout = stdout
	session.Stderr = stderr
	defer func() { record.Stdout = stdout.String(); record.Stderr = stderr.String() }()
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	var runErr error
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
waiting:
	for {
		select {
		case runErr = <-done:
			break waiting
		case <-ctx.Done():
			_ = client.Close()
			return combineCommandOutput(stdout.String(), stderr.String()), 124, fmt.Errorf("SSH command cancelled or timed out after %d seconds", timeout)
		case <-ticker.C:
			snapshot := *record
			snapshot.Stdout, snapshot.Stderr = stdout.String(), stderr.String()
			snapshot.Output = combineCommandOutput(snapshot.Stdout, snapshot.Stderr)
			a.auditMu.Lock()
			err := a.saveAuditLocked(snapshot)
			a.auditMu.Unlock()
			if err != nil {
				_ = client.Close()
				return snapshot.Output, -1, errors.New("audit persistence failed; connection closed")
			}
		}
	}

	output := combineCommandOutput(stdout.String(), stderr.String())
	if runErr == nil {
		return output, 0, nil
	}
	var exitError *ssh.ExitError
	if errors.As(runErr, &exitError) {
		return output, exitError.ExitStatus(), nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, 124, fmt.Errorf("SSH command timed out after %d seconds", timeout)
	}
	return output, 255, fmt.Errorf("SSH command failed: %w", runErr)
}

func combineCommandOutput(stdout, stderr string) string {
	if stderr == "" {
		return stdout
	}
	if stdout == "" {
		return "stderr:\n" + stderr
	}
	return stdout + "\n\nstderr:\n" + stderr
}
