package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

//go:embed agent_remote.py
var agentRemoteScript string

// Keep one small tool schema. Detailed usage belongs in README, not every call.
func agentTool() map[string]any {
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return map[string]any{
		"name":        "ssh_agent",
		"description": "Control remote coding agents in the target user's existing Herdr default session; never creates Herdr sessions or servers. action: start/list/status/read/prompt/keys/wait/interrupt/stop; host_id required. start needs cwd (kind defaults codex), others need agent_id except list. text submits a prompt; keys answers terminal dialogs. read returns a bounded snapshot. result + session_id polls Hub approval/execution; never blindly retry mutations. Requires Herdr and Python 3 on target.",
		"annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
		"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"action"}, "properties": map[string]any{
			"action":          map[string]any{"type": "string", "enum": []string{"start", "list", "status", "read", "prompt", "keys", "wait", "interrupt", "stop", "result"}},
			"host_id":         str("Host ID or unique name from ssh_list_hosts."),
			"agent_id":        str("Returned agent name or pane ID; optional unique name for start."),
			"cwd":             str("Absolute remote project/worktree directory; start only."),
			"kind":            map[string]any{"type": "string", "enum": []string{"codex", "claude", "opencode"}},
			"text":            str("Task for start or prompt (max 8 KiB)."),
			"keys":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 16, "description": "keys only: e.g. [\"down\",\"enter\"]."},
			"until":           map[string]any{"type": "string", "enum": []string{"idle", "done", "blocked", "working", "unknown"}, "description": "wait only; default waits for idle/done/blocked."},
			"timeout_seconds": map[string]any{"type": "integer", "minimum": 5, "maximum": 60, "description": "Control-call budget, capped by host; not agent task duration."},
			"lines":           map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "description": "read only; default 40, max output 16 KiB."},
			"offset":          map[string]any{"type": "integer", "minimum": 0, "description": "list pagination; use next_offset."},
			"session_id":      str("Hub execution ID for result; distinct from agent_id."),
		}},
	}
}

type agentRequest struct {
	Action         string   `json:"action"`
	HostID         string   `json:"host_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	Kind           string   `json:"kind,omitempty"`
	Text           string   `json:"text,omitempty"`
	Keys           []string `json:"keys,omitempty"`
	Until          string   `json:"until,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	Lines          int      `json:"lines,omitempty"`
	Offset         int      `json:"offset,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
}

var agentNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var agentPanePattern = regexp.MustCompile(`^w[0-9]+:p[0-9]+$`)
var agentKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9+_-]{1,32}$`)

func decodeAgentRequest(raw []byte) (agentRequest, error) {
	var req agentRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, errors.New("invalid ssh_agent arguments")
	}
	if dec.Decode(new(any)) != io.EOF {
		return req, errors.New("invalid ssh_agent arguments")
	}
	if req.Action == "result" {
		if !auditIDPattern.MatchString(req.SessionID) {
			return req, errors.New("result requires session_id from a previous ssh_agent call")
		}
		copy := req
		copy.Action = ""
		copy.SessionID = ""
		b, _ := json.Marshal(copy)
		if string(b) != `{"action":""}` {
			return req, errors.New("result accepts only action and session_id")
		}
		return req, nil
	}
	switch req.Action {
	case "start", "list", "status", "read", "prompt", "keys", "wait", "interrupt", "stop":
	default:
		return req, errors.New("unknown ssh_agent action")
	}
	if req.HostID == "" || len(req.HostID) > 128 || strings.ContainsRune(req.HostID, 0) {
		return req, errors.New("host_id required")
	}
	if req.SessionID != "" {
		return req, errors.New("session_id is only for result")
	}
	if req.AgentID != "" && !agentNamePattern.MatchString(req.AgentID) && !agentPanePattern.MatchString(req.AgentID) {
		return req, errors.New("invalid agent_id")
	}
	if req.Action != "start" && req.Action != "list" && req.AgentID == "" {
		return req, errors.New("agent_id required")
	}
	if req.Action == "list" && req.AgentID != "" {
		return req, errors.New("list does not accept agent_id")
	}
	if req.Action == "start" {
		if !path.IsAbs(req.Cwd) || len(req.Cwd) > 4096 || strings.ContainsAny(req.Cwd, "\x00\r\n") {
			return req, errors.New("start requires an absolute remote cwd")
		}
		if req.AgentID != "" && !agentNamePattern.MatchString(req.AgentID) {
			return req, errors.New("start agent_id must be a name, not a pane ID")
		}
		if req.Kind == "" {
			req.Kind = "codex"
		}
		if req.Kind != "codex" && req.Kind != "claude" && req.Kind != "opencode" {
			return req, errors.New("unsupported agent kind")
		}
	} else if req.Cwd != "" || req.Kind != "" {
		return req, errors.New("cwd and kind are only for start")
	}
	if len(req.Text) > 8192 || strings.ContainsRune(req.Text, 0) {
		return req, errors.New("text must be at most 8 KiB and contain no NUL")
	}
	if req.Action == "prompt" && strings.TrimSpace(req.Text) == "" {
		return req, errors.New("prompt requires text")
	}
	if req.Text != "" && req.Action != "start" && req.Action != "prompt" {
		return req, errors.New("text is only for start or prompt")
	}
	if req.Action == "keys" {
		if len(req.Keys) < 1 || len(req.Keys) > 16 {
			return req, errors.New("keys requires 1 to 16 key names")
		}
		for _, key := range req.Keys {
			if !agentKeyPattern.MatchString(key) {
				return req, errors.New("invalid key name")
			}
		}
	} else if len(req.Keys) > 0 {
		return req, errors.New("keys is only for keys action")
	}
	if req.Until != "" {
		if req.Action != "wait" {
			return req, errors.New("until is only for wait")
		}
		switch req.Until {
		case "idle", "done", "blocked", "working", "unknown":
		default:
			return req, errors.New("invalid until state")
		}
	}
	if req.Lines < 0 || req.Lines > 200 || (req.Lines != 0 && req.Action != "read") {
		return req, errors.New("lines is only for read and must be 1 to 200")
	}
	if req.Offset < 0 || (req.Offset != 0 && req.Action != "list") {
		return req, errors.New("offset is only for list and must be nonnegative")
	}
	if req.TimeoutSeconds != 0 && (req.TimeoutSeconds < 5 || req.TimeoutSeconds > 60) {
		return req, errors.New("timeout_seconds must be 5 to 60")
	}
	return req, nil
}

func (a *App) callAgentTool(raw json.RawMessage, ctx context.Context) (any, *jsonRPCError) {
	req, err := decodeAgentRequest(raw)
	if err != nil {
		return nil, &jsonRPCError{Code: -32602, Message: err.Error()}
	}
	if clientIDFromContext(ctx) == "" {
		return connectionToolResult(nil, errors.New("client authentication required")), nil
	}
	if req.Action == "result" {
		record, err := a.clientAudit(ctx, req.SessionID)
		if err == nil && record.Operation != "agent" {
			err = errors.New("not an ssh_agent execution")
		}
		if err != nil {
			return connectionToolResult(nil, err), nil
		}
		return agentToolResult(record), nil
	}
	req.HostID, err = a.resolveHostReference(ctx, req.HostID)
	if err != nil {
		return connectionToolResult(nil, err), nil
	}
	if req.Action == "start" && req.AgentID == "" {
		id, err := a.store.resourceID("agent")
		if err != nil {
			return connectionToolResult(nil, err), nil
		}
		req.AgentID = id
	}
	rawCommand, _ := json.Marshal(req)
	record, err := a.submitOperation(ctx, req.HostID, string(rawCommand), req.TimeoutSeconds, "agent", "")
	if err != nil {
		return connectionToolResult(nil, err), nil
	}
	return agentToolResult(record), nil
}

// Stable per Hub and host across restarts. All clients use the same Herdr
// default session, so serialize workspace creation for the whole host.
func (a *App) agentStartLockID(hostID string) string {
	mac := hmac.New(sha256.New, a.store.key)
	_, _ = fmt.Fprintf(mac, "ssh-hub-agent-start\x00%s", hostID)
	return "host-" + hex.EncodeToString(mac.Sum(nil)[:12])
}

func (a *App) runAgentOperation(ctx context.Context, host Host, key StoredKey, record *AuditSession) (string, int, error) {
	req, err := decodeAgentRequest([]byte(record.Command))
	if err != nil || req.Action == "result" || req.HostID != host.ID {
		return "", -1, errors.New("invalid audited agent request")
	}
	timeout := req.TimeoutSeconds
	if timeout == 0 {
		timeout = 30
	}
	if host.TimeoutSeconds > 0 && timeout > host.TimeoutSeconds {
		timeout = host.TimeoutSeconds
	}
	if req.Action == "start" && timeout < 10 {
		return "", -1, errors.New("starting an agent requires a control and host timeout of at least 10 seconds")
	}
	if timeout < 5 {
		return "", -1, errors.New("ssh_agent requires host command timeout of at least 5 seconds")
	}
	payload, _ := json.Marshal(map[string]any{"request": req, "lock_id": a.agentStartLockID(host.ID), "budget": timeout - 2})
	command := "python3 -c " + shellQuote(agentRemoteScript) + " " + shellQuote(string(payload))
	output, code, err := a.runSSHCommand(ctx, host, key, command, timeout, record)
	if err == nil && code == 0 {
		var remote map[string]any
		if json.Unmarshal([]byte(record.Stdout), &remote) != nil || remote == nil {
			err = errors.New("invalid Herdr controller response; inspect the audit before retrying")
		} else if remote["error"] != nil {
			code = 1
		}
	}
	return output, code, err
}

func agentToolResult(record AuditSession) map[string]any {
	var req agentRequest
	_ = json.Unmarshal([]byte(record.Command), &req)
	result := map[string]any{"session_id": record.ID, "status": record.Status, "action": req.Action}
	if req.HostID != "" {
		result["host_id"] = req.HostID
	}
	if req.AgentID != "" {
		result["agent_id"] = req.AgentID
	}
	if record.Status == "pending" || record.Status == "running" {
		result["next"] = map[string]string{"action": "result", "session_id": record.ID}
	}
	if record.Stdout != "" {
		var remote map[string]any
		if err := json.Unmarshal([]byte(record.Stdout), &remote); err == nil {
			result["result"] = remote
		} else {
			result["error"] = "Invalid remote response; inspect audit with this session_id. Do not blindly retry."
		}
	}
	if record.Error != "" {
		result["error"] = record.Error
	}
	if record.Status == "failed" {
		result["exit_code"] = record.ExitCode
		if _, ok := result["error"]; !ok && record.Stderr != "" {
			result["error"] = truncateAgentText(record.Stderr, 2048)
		}
		result["retry_hint"] = "Inspect status/list before retrying; remote actions may already have happened."
	}
	data, _ := json.Marshal(result)
	// One JSON text block avoids repeating terminal output in structuredContent.
	return map[string]any{"content": []map[string]string{{"type": "text", "text": string(data)}}, "isError": record.Status != "completed" && record.Status != "pending" && record.Status != "running"}
}
func truncateAgentText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…[truncated]"
}
