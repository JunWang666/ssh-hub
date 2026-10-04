package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed agent_scan_remote.py
var agentScanRemoteScript string

type AgentScanSnapshot struct {
	ScannedAt *time.Time      `json:"scannedAt,omitempty"`
	Hosts     []AgentHostScan `json:"hosts"`
	Total     int             `json:"total"`
}

type AgentHostScan struct {
	HostID   string         `json:"hostId"`
	HostName string         `json:"hostName"`
	Address  string         `json:"address"`
	Status   string         `json:"status"`
	Error    string         `json:"error,omitempty"`
	Sessions []AgentSession `json:"sessions"`
}

type AgentSession struct {
	Name   string       `json:"name"`
	Error  string       `json:"error,omitempty"`
	Agents []AgentBrief `json:"agents"`
}

type AgentBrief struct {
	AgentID string `json:"agentId"`
	PaneID  string `json:"paneId"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Cwd     string `json:"cwd,omitempty"`
}

func scanAgentError(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 512 {
		return text[:512]
	}
	return text
}

func (a *App) scanAgentHost(ctx context.Context, host Host) AgentHostScan {
	result := AgentHostScan{HostID: host.ID, HostName: host.Name, Address: host.Address, Status: "online", Sessions: []AgentSession{}}
	var key StoredKey
	err := a.store.view(func(s State) error {
		var ok bool
		key, ok = s.Keys[host.KeyID]
		if !ok {
			return errors.New("configured SSH key not found")
		}
		return nil
	})
	if err != nil {
		result.Status, result.Error = "error", err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	command := "python3 -c " + shellQuote(agentScanRemoteScript)
	record := AuditSession{ClientName: "admin agent scan", HostID: host.ID}
	_, _, err = a.runSSHCommand(ctx, host, key, command, 10, &record)
	if err != nil {
		result.Status, result.Error = "offline", scanAgentError(err.Error())
		return result
	}
	var remote struct {
		Sessions  []AgentSession `json:"sessions"`
		Error     string         `json:"error"`
		Truncated bool           `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(record.Stdout), &remote); err != nil {
		result.Status, result.Error = "error", "invalid Herdr scanner response"
		return result
	}
	if remote.Error != "" {
		result.Status, result.Error = "unavailable", scanAgentError(remote.Error)
		return result
	}
	result.Sessions = remote.Sessions
	if remote.Truncated {
		result.Error = "session list truncated at 32 running sessions"
	}
	return result
}

func (a *App) agentScanSnapshot() AgentScanSnapshot {
	a.agentScanMu.RLock()
	defer a.agentScanMu.RUnlock()
	if a.agentScan.Hosts == nil {
		return AgentScanSnapshot{Hosts: []AgentHostScan{}}
	}
	return a.agentScan
}

func (a *App) handleAgentSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.agentScanSnapshot())
}

func (a *App) handleAgentSessionScan(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	if !a.agentScanRun.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Agent 扫描正在进行，请稍后刷新"})
		return
	}
	defer a.agentScanRun.Unlock()
	var hosts []Host
	_ = a.store.view(func(s State) error {
		for _, host := range s.Hosts {
			hosts = append(hosts, host)
		}
		return nil
	})
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	if len(hosts) > 128 {
		hosts = hosts[:128]
	}
	results := make([]AgentHostScan, len(hosts))
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	slots := make(chan struct{}, 8)
	var wg sync.WaitGroup
	scanning := true
	for i, host := range hosts {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			scanning = false
			for j := i; j < len(hosts); j++ {
				results[j] = AgentHostScan{HostID: hosts[j].ID, HostName: hosts[j].Name, Address: hosts[j].Address, Status: "skipped", Error: "scan deadline exceeded", Sessions: []AgentSession{}}
			}
		}
		if !scanning {
			break
		}
		wg.Add(1)
		go func(index int, h Host) {
			defer wg.Done()
			defer func() { <-slots }()
			results[index] = a.scanAgentHost(ctx, h)
		}(i, host)
	}
	wg.Wait()
	total := 0
	for _, host := range results {
		for _, session := range host.Sessions {
			total += len(session.Agents)
		}
	}
	now := time.Now().UTC()
	snapshot := AgentScanSnapshot{ScannedAt: &now, Hosts: results, Total: total}
	a.agentScanMu.Lock()
	a.agentScan = snapshot
	a.agentScanMu.Unlock()
	writeJSON(w, http.StatusOK, snapshot)
}
