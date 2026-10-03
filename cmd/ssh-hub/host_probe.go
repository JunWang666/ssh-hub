package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// Stop at host-key verification, before attempting user authentication.
func probeHost(ctx context.Context, address string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", "", err
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var fingerprint, algorithm string
	_, _, _, err = ssh.NewClientConn(connection, address, &ssh.ClientConfig{
		User: "ssh-hub-hostkey-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint, algorithm = ssh.FingerprintSHA256(key), key.Type()
			return errors.New("host key collected; authentication intentionally skipped")
		},
	})
	if fingerprint == "" {
		return "", "", err
	}
	return fingerprint, algorithm, nil
}

func (a *App) handleProbeHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input struct {
		Address string `json:"address"`
	}
	if decodeJSON(r, &input) != nil {
		writeJSON(w, 400, map[string]string{"error": "地址无效"})
		return
	}
	address, err := normalizeSSHAddress(input.Address)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "地址无效"})
		return
	}
	fingerprint, algorithm, err := probeHost(r.Context(), address)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "无法获取主机指纹: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"address": address, "fingerprint": fingerprint, "algorithm": algorithm})
}
