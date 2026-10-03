package main

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type HostHealth struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checkedAt"`
	LatencyMS int64     `json:"latencyMs"`
	Error     string    `json:"error,omitempty"`
}

func (a *App) checkHost(ctx context.Context, host Host) HostHealth {
	start := time.Now()
	fingerprint, _, err := probeHost(ctx, host.Address)
	h := HostHealth{Status: "online", CheckedAt: time.Now().UTC(), LatencyMS: time.Since(start).Milliseconds()}
	if err != nil {
		h.Status = "offline"
		h.Error = err.Error()
	} else if fingerprint != host.HostKeyFingerprint {
		h.Status = "fingerprint_changed"
		h.Error = "服务器指纹与已确认指纹不符"
	}
	a.healthMu.Lock()
	a.health[host.ID] = h
	a.healthMu.Unlock()
	return h
}
func (a *App) healthSnapshot() map[string]HostHealth {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	result := map[string]HostHealth{}
	for id, h := range a.health {
		result[id] = h
	}
	return result
}
func (a *App) checkAllHosts(ctx context.Context) {
	if !a.healthRun.TryLock() {
		return
	}
	defer a.healthRun.Unlock()
	var hosts []Host
	_ = a.store.view(func(s State) error {
		for _, h := range s.Hosts {
			hosts = append(hosts, h)
		}
		return nil
	})
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, h := range hosts {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(h Host) { defer wg.Done(); defer func() { <-slots }(); a.checkHost(ctx, h) }(h)
	}
	wg.Wait()
}
func (a *App) handleHostHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if _, ok := a.checkCSRF(w, r); !ok {
			return
		}
	} else {
		if _, ok := a.requireSession(w, r); !ok {
			return
		}
	}
	id := r.PathValue("id")
	if id == "" {
		if r.Method == http.MethodPost {
			a.checkAllHosts(r.Context())
		}
		writeJSON(w, 200, a.healthSnapshot())
		return
	}
	var host Host
	_ = a.store.view(func(s State) error { host = s.Hosts[id]; return nil })
	if host.ID == "" {
		writeJSON(w, 404, map[string]string{"error": "主机不存在"})
		return
	}
	if r.Method == http.MethodPost {
		writeJSON(w, 200, a.checkHost(r.Context(), host))
		return
	}
	h, ok := a.healthSnapshot()[id]
	if !ok {
		h.Status = "unknown"
	}
	writeJSON(w, 200, h)
}

func (a *App) monitor(ctx context.Context) {
	go a.checkAllHosts(ctx)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			a.closeAllConnections("service stopped")
			return
		case <-tick.C:
			a.checkConnections(ctx)
			n++
			if n%2 == 0 {
				go a.checkAllHosts(ctx)
			}
		}
	}
}
