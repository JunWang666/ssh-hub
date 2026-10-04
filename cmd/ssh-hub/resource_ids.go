package main

import (
	"context"
	"errors"
	"fmt"
)

// Resource IDs are references, never credentials. Persist allocation before use
// so concurrent calls and restarts cannot reuse an ID. Authentication tokens
// continue to use cryptographic randomness.
func (s *Store) resourceID(kind string) (string, error) {
	var id string
	err := s.update(func(state *State) error {
		if state.ResourceCounters == nil {
			state.ResourceCounters = map[string]uint64{}
		}
		n := state.ResourceCounters[kind] + 1
		if n == 0 {
			return errors.New("resource ID space exhausted")
		}
		state.ResourceCounters[kind] = n
		id = fmt.Sprintf("%s-%d", kind, n)
		return nil
	})
	return id, err
}

// Exact IDs take precedence. Names must identify exactly one accessible host;
// never guess. Exact IDs still pass through the audited authorization check.
func (a *App) resolveHostReference(ctx context.Context, ref string) (string, error) {
	var id string
	err := a.store.view(func(state State) error {
		client, ok := state.Clients[clientIDFromContext(ctx)]
		if !ok {
			return errors.New("client authentication required")
		}
		if host, ok := state.Hosts[ref]; ok {
			id = host.ID
			return nil
		}
		for _, host := range state.Hosts {
			if host.Name == ref && clientAllowsHost(client, host.ID) {
				if id != "" {
					return errors.New("ambiguous host name; use an id from ssh_list_hosts")
				}
				id = host.ID
			}
		}
		if id == "" {
			return errors.New("host not found or not allowed; use ssh_list_hosts")
		}
		return nil
	})
	return id, err
}
