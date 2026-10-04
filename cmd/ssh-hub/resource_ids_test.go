package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestResourceIDsConcurrentAndRestart(t *testing.T) {
	a := featureApp(t)
	ids := make(chan string, 24)
	var wg sync.WaitGroup
	for i := 0; i < cap(ids); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := a.store.resourceID("run")
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] || !auditIDPattern.MatchString(id) {
			t.Fatalf("invalid/duplicate ID %s", id)
		}
		seen[id] = true
	}
	store, err := openStore(filepath.Dir(a.store.path))
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.resourceID("run")
	if err != nil || id != "run-25" {
		t.Fatalf("restart: %s %v", id, err)
	}
}

func TestHostReferenceNamesAndPermissions(t *testing.T) {
	a := featureApp(t)
	err := a.store.update(func(s *State) error {
		s.Hosts["old-random-id"] = Host{ID: "old-random-id", Name: "production"}
		s.Hosts["host-2"] = Host{ID: "host-2", Name: "production"}
		s.Clients["owner"] = OAuthClient{ID: "owner", HostAccessConfigured: true, AllowedHostIDs: []string{"old-random-id"}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), clientContextKey{}, "owner")
	if id, err := a.resolveHostReference(ctx, "production"); err != nil || id != "old-random-id" {
		t.Fatalf("name: %s %v", id, err)
	}
	if _, err := a.resolveHostReference(context.Background(), "production"); err == nil {
		t.Fatal("unauthenticated lookup")
	}
	err = a.store.update(func(s *State) error {
		c := s.Clients["owner"]
		c.AllowedHostIDs = append(c.AllowedHostIDs, "host-2")
		s.Clients["owner"] = c
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.resolveHostReference(ctx, "production"); err == nil {
		t.Fatal("ambiguous name accepted")
	}
	if id, err := a.resolveHostReference(ctx, "old-random-id"); err != nil || id != "old-random-id" {
		t.Fatalf("legacy id: %s %v", id, err)
	}
}

func TestMixedAuditIDsPagination(t *testing.T) {
	a := featureApp(t)
	base := time.Now().Add(-time.Hour)
	a.auditMu.Lock()
	for i := 0; i < 55; i++ {
		id := fmt.Sprintf("run-%d", i+1)
		if i == 30 {
			id = "20260101T000000_abcdefghijklmnop"
		}
		r := AuditSession{ID: id, ClientID: "owner", Status: "completed", CreatedAt: base.Add(time.Duration(i) * time.Second)}
		if err := a.saveAuditLocked(r); err != nil {
			a.auditMu.Unlock()
			t.Fatal(err)
		}
	}
	a.auditMu.Unlock()
	records, next, err := a.clientAuditList("owner", "", "", "")
	if err != nil || len(records) != 50 || records[0].ID != "run-55" || next != "run-6" {
		t.Fatalf("first page len=%d next=%s err=%v", len(records), next, err)
	}
	records, next, err = a.clientAuditList("owner", next, "", "")
	if err != nil || len(records) != 5 || records[0].ID != "run-5" || next != "" {
		t.Fatalf("second page len=%d next=%s err=%v", len(records), next, err)
	}
	if _, _, err := a.clientAuditList("other", "run-6", "", ""); err == nil {
		t.Fatal("cross-client cursor accepted")
	}
}

func TestMCPExecInfersHostFromShell(t *testing.T) {
	a, h, ctx, _, stop := persistentFixture(t)
	defer stop()
	call := func(name string, args map[string]any, ctx context.Context) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
		result, rpcErr := a.callTool(raw, ctx)
		if rpcErr != nil {
			t.Fatal(rpcErr)
		}
		return result.(map[string]any)
	}
	opened := call("ssh_open_session", map[string]any{"host_id": h.Name}, ctx)
	data := opened["structuredContent"].(map[string]any)
	if data["status"] != "completed" || data["connection_id"] != "shell-1" {
		t.Fatal(data)
	}
	args := map[string]any{"connection_id": data["connection_id"], "command": "printf hello"}
	result := call("ssh_exec", args, ctx)["structuredContent"].(map[string]any)
	if result["status"] != "completed" || result["stdout"] != "hello" {
		t.Fatal(result)
	}
	for _, other := range []context.Context{context.Background(), context.WithValue(context.Background(), clientContextKey{}, "other")} {
		if call("ssh_exec", args, other)["isError"] != true {
			t.Fatal("cross-client shell access")
		}
	}
}

func TestAuditPendingNextCall(t *testing.T) {
	for _, status := range []string{"pending", "running"} {
		result := auditToolResult(AuditSession{ID: "run-7", Status: status})
		next := result["structuredContent"].(map[string]any)["next_call"].(map[string]any)
		if next["name"] != "ssh_session_status" || next["arguments"].(map[string]string)["session_id"] != "run-7" {
			t.Fatal(next)
		}
	}
	if _, ok := auditToolResult(AuditSession{Status: "completed"})["structuredContent"].(map[string]any)["next_call"]; ok {
		t.Fatal("completed operation suggests polling")
	}
}
