package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Resolve from one state snapshot before opening any connections. Limit the route
// and reject cycles even if a state file was modified outside the API.
func jumpRoute(s State, host Host) ([]Host, error) {
	seen := map[string]bool{host.ID: true}
	var route []Host
	for id := host.JumpHostID; id != ""; {
		if seen[id] || len(route) >= 8 {
			return nil, errors.New("跳板路径存在循环或超过 8 层")
		}
		seen[id] = true
		jump, ok := s.Hosts[id]
		if !ok {
			return nil, errors.New("跳板主机不存在")
		}
		route = append(route, jump)
		id = jump.JumpHostID
	}
	return route, nil
}

// Closing the target transport also closes every authenticated jump connection.
type jumpConn struct {
	net.Conn
	parent *ssh.Client
	once   sync.Once
}

func (c *jumpConn) Close() error {
	var err error
	c.once.Do(func() { err = c.parent.Close(); _ = c.Conn.Close() })
	return err
}

func (a *App) dialHostTransport(ctx context.Context, host Host) (net.Conn, error) {
	var route []Host
	var configs []*ssh.ClientConfig
	err := a.store.view(func(s State) error {
		var err error
		route, err = jumpRoute(s, host)
		if err != nil {
			return err
		}
		for _, jump := range route {
			signer, err := a.keySigner(s.Keys[jump.KeyID])
			if err != nil {
				return fmt.Errorf("jump host %s key: %w", jump.Name, err)
			}
			fingerprint := jump.HostKeyFingerprint
			configs = append(configs, &ssh.ClientConfig{User: jump.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				if ssh.FingerprintSHA256(key) != fingerprint {
					return errors.New("jump host key fingerprint mismatch")
				}
				return nil
			}})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	address := host.Address
	if len(route) > 0 {
		address = route[len(route)-1].Address
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	// Keep cancellation active during channel opens and all jump handshakes.
	root := conn
	stop := context.AfterFunc(ctx, func() { _ = root.Close() })
	defer stop()
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	for i := len(route) - 1; i >= 0; i-- {
		cc, chans, reqs, err := ssh.NewClientConn(conn, route[i].Address, configs[i])
		if err != nil {
			return nil, fmt.Errorf("jump host %s: %w", route[i].Name, err)
		}
		client := ssh.NewClient(cc, chans, reqs)
		target := host.Address
		if i > 0 {
			target = route[i-1].Address
		}
		tunnel, err := client.DialContext(ctx, "tcp", target)
		if err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("jump host %s forwarding: %w", route[i].Name, err)
		}
		conn = &jumpConn{Conn: tunnel, parent: client}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	success = true
	return conn, nil
}
