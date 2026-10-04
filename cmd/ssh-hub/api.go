package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)
var dnsLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

type publicKey struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
	Source         string    `json:"source"`
	Path           string    `json:"path,omitempty"`
	PublicKey      string    `json:"publicKey,omitempty"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
	InstallURL     string    `json:"installURL,omitempty"`
	PublicKeyURL   string    `json:"publicKeyURL,omitempty"`
	InstallCommand string    `json:"installCommand,omitempty"`
}

type publicHost struct {
	JumpHostID         string    `json:"jumpHostId,omitempty"`
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Address            string    `json:"address"`
	Username           string    `json:"username"`
	KeyID              string    `json:"keyId"`
	KeyName            string    `json:"keyName"`
	HostKeyFingerprint string    `json:"hostKeyFingerprint"`
	TimeoutSeconds     int       `json:"timeoutSeconds"`
	CreatedAt          time.Time `json:"createdAt"`
}

type publicClient struct {
	HostAccessConfigured bool      `json:"hostAccessConfigured"`
	AllowedHostIDs       []string  `json:"allowedHostIds"`
	RequireApproval      bool      `json:"requireApproval"`
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	RedirectURIs         []string  `json:"redirectURIs"`
	CreatedAt            time.Time `json:"createdAt"`
}

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireSession(w, r); !ok {
		return
	}
	var keys []publicKey
	var hosts []publicHost
	var clients []publicClient
	_ = a.store.view(func(state State) error {
		for _, key := range state.Keys {
			keys = append(keys, a.keyInfo(key))
		}
		for _, host := range state.Hosts {
			key := state.Keys[host.KeyID]
			hosts = append(hosts, publicHost{
				JumpHostID: host.JumpHostID, ID: host.ID, Name: host.Name, Address: host.Address, Username: host.Username,
				KeyID: host.KeyID, KeyName: key.Name, HostKeyFingerprint: host.HostKeyFingerprint,
				TimeoutSeconds: host.TimeoutSeconds, CreatedAt: host.CreatedAt,
			})
		}
		for _, client := range state.Clients {
			clients = append(clients, publicClient{HostAccessConfigured: client.HostAccessConfigured, AllowedHostIDs: client.AllowedHostIDs, RequireApproval: client.RequireApproval, ID: client.ID, Name: client.Name, RedirectURIs: client.RedirectURIs, CreatedAt: client.CreatedAt})
		}
		return nil
	})
	if keys == nil {
		keys = []publicKey{}
	}
	if hosts == nil {
		hosts = []publicHost{}
	}
	if clients == nil {
		clients = []publicClient{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "hosts": hosts, "clients": clients})
}

type createKeyRequest struct {
	Source     string `json:"source"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`
}

func (a *App) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var request createKeyRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式无效或内容过大"})
		return
	}
	key, err := a.createKey(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, a.keyInfo(key))
}

func parsePrivateKey(privateKey, passphrase string) (ssh.Signer, error) {
	if signer, err := ssh.ParsePrivateKey([]byte(privateKey)); err == nil {
		return signer, nil
	}
	if passphrase == "" {
		return nil, errors.New("invalid or encrypted private key")
	}
	return ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
}

func (a *App) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	var removed StoredKey
	err := a.store.update(func(state *State) error {
		if _, ok := state.Keys[id]; !ok {
			return errors.New("密钥不存在")
		}
		for _, host := range state.Hosts {
			if host.KeyID == id {
				return errors.New("该密钥仍被 SSH 主机使用")
			}
		}
		removed = state.Keys[id]
		delete(state.Keys, id)
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if removed.Source == "generated" {
		_ = os.Remove(filepath.Join(a.generatedKeysDir(), removed.Path) + ".pub")
		if err := os.Remove(filepath.Join(a.generatedKeysDir(), removed.Path)); err != nil && !os.IsNotExist(err) {
			log.Printf("remove generated key file %s: %v", removed.ID, err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type createHostRequest struct {
	JumpHostID         string `json:"jumpHostId"`
	Name               string `json:"name"`
	Address            string `json:"address"`
	Username           string `json:"username"`
	KeyID              string `json:"keyID"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
	TimeoutSeconds     int    `json:"timeoutSeconds"`
}

func (a *App) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var request createHostRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式无效"})
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Username = strings.TrimSpace(request.Username)
	request.HostKeyFingerprint = strings.TrimSpace(request.HostKeyFingerprint)
	address, err := normalizeSSHAddress(request.Address)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "地址必须是有效的主机名或 IP，可选端口；默认端口为 22"})
		return
	}
	if request.Name == "" || len(request.Name) > 80 || !usernamePattern.MatchString(request.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请填写有效的名称和 SSH 用户名"})
		return
	}
	if !validFingerprint(request.HostKeyFingerprint) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "服务器指纹格式无效，请使用 SHA256:... 格式"})
		return
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = 30
	}
	if request.TimeoutSeconds < 1 || request.TimeoutSeconds > 300 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "命令超时必须在 1 到 300 秒之间"})
		return
	}
	id, err := a.store.resourceID("host")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "无法创建主机记录"})
		return
	}
	host := Host{
		JumpHostID: request.JumpHostID, ID: id, Name: request.Name, Address: address, Username: request.Username,
		KeyID: request.KeyID, HostKeyFingerprint: request.HostKeyFingerprint,
		TimeoutSeconds: request.TimeoutSeconds, CreatedAt: time.Now().UTC(),
	}
	if err := a.store.update(func(state *State) error {
		if _, ok := state.Keys[host.KeyID]; !ok {
			return errors.New("请选择一个已保存的 SSH 密钥")
		}
		if _, err := jumpRoute(*state, host); err != nil {
			return err
		}
		state.Hosts[host.ID] = host
		return nil
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	keyName := ""
	_ = a.store.view(func(state State) error { keyName = state.Keys[host.KeyID].Name; return nil })
	writeJSON(w, http.StatusCreated, publicHost{
		JumpHostID: host.JumpHostID, ID: host.ID, Name: host.Name, Address: host.Address, Username: host.Username,
		KeyID: host.KeyID, KeyName: keyName, HostKeyFingerprint: host.HostKeyFingerprint,
		TimeoutSeconds: host.TimeoutSeconds, CreatedAt: host.CreatedAt,
	})
}

func normalizeSSHAddress(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" || strings.ContainsAny(input, " \t\r\n/@") {
		return "", errors.New("invalid host address")
	}
	host := ""
	port := "22"
	if parsed := net.ParseIP(input); parsed != nil && strings.Contains(input, ":") {
		host = parsed.String()
	} else if strings.Count(input, ":") == 0 {
		host = input
	} else {
		var err error
		host, port, err = net.SplitHostPort(input)
		if err != nil {
			return "", err
		}
	}
	if ip := net.ParseIP(host); ip == nil {
		if len(host) == 0 || len(host) > 253 {
			return "", errors.New("invalid host")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if !dnsLabelPattern.MatchString(label) {
				return "", errors.New("invalid hostname")
			}
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(decoded) == 32
}

func (a *App) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	err := a.store.update(func(state *State) error {
		if _, ok := state.Hosts[r.PathValue("id")]; !ok {
			return errors.New("主机不存在")
		}
		for _, host := range state.Hosts {
			if host.JumpHostID == r.PathValue("id") {
				return errors.New("此主机仍被用作跳板，请先删除依赖主机")
			}
		}
		delete(state.Hosts, r.PathValue("id"))
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	a.enforceConnectionPolicies()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	err := a.store.update(func(state *State) error {
		id := r.PathValue("id")
		if _, ok := state.Clients[id]; !ok {
			return errors.New("客户端不存在")
		}
		delete(state.Clients, id)
		for digest, grant := range state.DeviceGrants {
			if grant.ClientID == id {
				delete(state.DeviceGrants, digest)
			}
		}
		for digest, code := range state.Codes {
			if code.ClientID == id {
				delete(state.Codes, digest)
			}
		}
		for digest, token := range state.Tokens {
			if token.ClientID == id {
				delete(state.Tokens, digest)
			}
		}
		for digest, token := range state.RefreshTokens {
			if token.ClientID == id {
				delete(state.RefreshTokens, digest)
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	a.enforceConnectionPolicies()
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("multiple JSON values are not allowed")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
