package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func (a *App) generatedKeysDir() string { return filepath.Join(filepath.Dir(a.store.path), "keys") }

func readKeyFile(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256*1024 {
		return nil, errors.New("密钥必须是小于 256 KiB 的普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(f, 256*1024+1))
	if len(data) > 256*1024 {
		return nil, errors.New("密钥文件过大")
	}
	return data, err
}

func (a *App) keySigner(key StoredKey) (ssh.Signer, error) {
	var material keyMaterial
	if key.Secret != "" {
		secret, err := a.store.decryptSecret(key.Secret)
		if err != nil {
			return nil, errors.New("无法解密密钥口令")
		}
		if err := json.Unmarshal(secret, &material); err != nil {
			return nil, err
		}
	}
	if key.Source == "mounted" || key.Source == "generated" {
		dir := a.keysDir
		if key.Source == "generated" {
			dir = a.generatedKeysDir()
		}
		data, err := readKeyFile(dir, key.Path)
		if err != nil {
			return nil, fmt.Errorf("无法读取密钥文件: %w", err)
		}
		material.PrivateKey = string(data)
	}
	signer, err := parsePrivateKey(material.PrivateKey, material.Passphrase)
	if err != nil {
		return nil, err
	}
	if key.PublicKey != "" && strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != strings.TrimSpace(key.PublicKey) {
		return nil, errors.New("密钥文件已改变，请重新登记密钥并安装新公钥")
	}
	return signer, nil
}

func (a *App) createKey(request createKeyRequest) (StoredKey, error) {
	var key StoredKey
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 80 {
		return key, errors.New("请填写密钥名称（最多 80 字符）")
	}
	if request.Source == "" {
		request.Source = "imported"
	} // Existing API clients.
	if request.Source != "generated" && request.Source != "mounted" && request.Source != "imported" {
		return key, errors.New("未知密钥来源")
	}
	id, err := randomToken(18)
	if err != nil {
		return key, err
	}
	token, err := randomToken(32)
	if err != nil {
		return key, err
	}
	key = StoredKey{ID: id, Name: request.Name, Source: request.Source, CreatedAt: time.Now().UTC(), InstallToken: token}
	material := keyMaterial{Passphrase: request.Passphrase}
	generatedPath := ""
	saved := false
	defer func() {
		if generatedPath != "" && !saved {
			_ = os.Remove(generatedPath)
			_ = os.Remove(generatedPath + ".pub")
		}
	}()
	switch request.Source {
	case "generated":
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return key, err
		}
		block, err := ssh.MarshalPrivateKey(private, "ssh-hub")
		if err != nil {
			return key, err
		}
		if err := os.MkdirAll(a.generatedKeysDir(), 0700); err != nil {
			return key, err
		}
		key.Path = id + "_ed25519"
		generatedPath = filepath.Join(a.generatedKeysDir(), key.Path)
		f, err := os.OpenFile(generatedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			generatedPath = ""
			return key, err
		}
		data := pem.EncodeToMemory(block)
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return key, err
		}
		if closeErr != nil {
			return key, closeErr
		}
	case "mounted":
		if a.keysDir == "" {
			return key, errors.New("未配置 SSHHUB_KEYS_DIR")
		}
		key.Path = strings.TrimSpace(request.Path)
		if filepath.IsAbs(key.Path) {
			key.Path, err = filepath.Rel(a.keysDir, key.Path)
			if err != nil {
				return key, err
			}
		}
		if key.Path == "" {
			return key, errors.New("请填写挂载目录中的密钥文件名")
		}
	case "imported":
		material.PrivateKey = strings.TrimSpace(request.PrivateKey)
	}
	if request.Source != "generated" {
		data, err := json.Marshal(material)
		if err != nil {
			return key, err
		}
		key.Secret, err = a.store.encryptSecret(data)
		if err != nil {
			return key, err
		}
	}
	signer, err := a.keySigner(key)
	if err != nil {
		return key, fmt.Errorf("密钥无法使用: %w", err)
	}
	key.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if key.Source == "generated" {
		if err := os.WriteFile(generatedPath+".pub", []byte(key.PublicKey+"\n"), 0600); err != nil {
			return key, err
		}
	}
	if err := a.store.update(func(state *State) error { state.Keys[id] = key; return nil }); err != nil {
		return key, err
	}
	saved = true
	return key, nil
}

func (a *App) keyInfo(key StoredKey) publicKey {
	info := publicKey{ID: key.ID, Name: key.Name, CreatedAt: key.CreatedAt, Source: key.Source, PublicKey: key.PublicKey}
	if info.Source == "" {
		info.Source = "imported"
	}
	if key.Source == "mounted" {
		info.Path = filepath.Join(a.keysDir, key.Path)
	}
	if key.Source == "generated" {
		info.Path = filepath.Join(a.generatedKeysDir(), key.Path)
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey)); err == nil {
		info.Fingerprint = ssh.FingerprintSHA256(pub)
	}
	if key.InstallToken != "" {
		info.InstallURL = a.publicURL + "/install/" + key.InstallToken
		info.PublicKeyURL = a.publicURL + "/public-keys/" + key.InstallToken
		info.InstallCommand = "curl -fsSL " + shellQuote(info.InstallURL) + " | sh"
	}
	return info
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func (a *App) handleKeyInstallLink(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.checkCSRF(w, r); !ok {
		return
	}
	var key StoredKey
	_ = a.store.view(func(state State) error { key = state.Keys[r.PathValue("id")]; return nil })
	if key.ID == "" {
		http.NotFound(w, r)
		return
	}
	signer, err := a.keySigner(key)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	key.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if key.InstallToken == "" {
		key.InstallToken, err = randomToken(32)
	}
	if err == nil {
		err = a.store.update(func(state *State) error {
			if _, ok := state.Keys[key.ID]; !ok {
				return errors.New("密钥已删除")
			}
			state.Keys[key.ID] = key
			return nil
		})
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "无法生成安装链接"})
		return
	}
	writeJSON(w, 200, a.keyInfo(key))
}

func (a *App) publishedKey(token string) string {
	if len(token) != 43 {
		return ""
	}
	var public string
	_ = a.store.view(func(state State) error {
		for _, key := range state.Keys {
			if key.InstallToken == token {
				public = key.PublicKey
				break
			}
		}
		return nil
	})
	return public
}

func (a *App) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	key := a.publishedKey(r.PathValue("token"))
	if key == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, key+"\n")
}

func installScript(key string) string {
	return "#!/bin/sh\nset -eu\numask 077\nkey=" + shellQuote(key) + `
ssh_dir="${HOME:?HOME is required}/.ssh"
mkdir -p "$ssh_dir"
chmod 700 "$ssh_dir"
auth_file="$ssh_dir/authorized_keys"
touch "$auth_file"
chmod 600 "$auth_file"
key_type=$(printf '%s\n' "$key" | awk '{print $1}')
key_blob=$(printf '%s\n' "$key" | awk '{print $2}')
if ! awk -v type="$key_type" -v blob="$key_blob" '{for(i=1;i<NF;i++) if($i == type && $(i+1) == blob) found=1} END {exit !found}' "$auth_file"; then
  printf '\n%s\n' "$key" >> "$auth_file"
fi
printf 'SSH Hub public key installed for %s\n' "$(id -un)"
printf 'Server host key fingerprints (for SSH Hub host configuration):\n'
for pub in /etc/ssh/ssh_host_*_key.pub; do
  [ -r "$pub" ] && ssh-keygen -lf "$pub" || true
done
`
}

func (a *App) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	key := a.publishedKey(r.PathValue("token"))
	if key == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, installScript(key))
}
