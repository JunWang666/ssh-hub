package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type State struct {
	PasswordHash  string                  `json:"password_hash,omitempty"`
	Hosts         map[string]Host         `json:"hosts"`
	Keys          map[string]StoredKey    `json:"keys"`
	Clients       map[string]OAuthClient  `json:"clients"`
	Codes         map[string]AuthCode     `json:"codes"`
	Tokens        map[string]AccessToken  `json:"tokens"`
	RefreshTokens map[string]RefreshToken `json:"refresh_tokens"`
}

type StoredKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

type Host struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Address            string    `json:"address"`
	Username           string    `json:"username"`
	KeyID              string    `json:"key_id"`
	HostKeyFingerprint string    `json:"host_key_fingerprint"`
	TimeoutSeconds     int       `json:"timeout_seconds"`
	CreatedAt          time.Time `json:"created_at"`
}

type OAuthClient struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	RedirectURIs   []string  `json:"redirect_uris"`
	RefreshEnabled bool      `json:"refresh_enabled,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type AuthCode struct {
	ClientID    string    `json:"client_id"`
	RedirectURI string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"`
	Scope       string    `json:"scope"`
	Resource    string    `json:"resource"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type AccessToken struct {
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RefreshToken struct {
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	Resource  string    `json:"resource"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	key   []byte
	state State
}

func openStore(dir string) (*Store, error) {
	masterKeyPath := filepath.Join(dir, "master.key")
	statePath := filepath.Join(dir, "state.json")
	if _, err := os.Stat(statePath); err == nil {
		if _, keyErr := os.Stat(masterKeyPath); errors.Is(keyErr, os.ErrNotExist) {
			return nil, errors.New("master.key is missing while state.json exists; refusing to create a replacement key")
		}
	}
	masterKey, err := loadOrCreateMasterKey(masterKeyPath)
	if err != nil {
		return nil, err
	}
	s := &Store{path: statePath, key: masterKey}
	data, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read state: %w", err)
	}
	if len(data) > 0 {
		if err := os.Chmod(s.path, 0o600); err != nil {
			return nil, fmt.Errorf("restrict state file permissions: %w", err)
		}
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("parse state: %w", err)
		}
	}
	normalizeState(&s.state)
	if len(data) == 0 {
		if err := s.saveLocked(s.state); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func loadOrCreateMasterKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("%s must contain a 32-byte key", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateMasterKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create encryption key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func normalizeState(state *State) {
	if state.Hosts == nil {
		state.Hosts = map[string]Host{}
	}
	if state.Keys == nil {
		state.Keys = map[string]StoredKey{}
	}
	if state.Clients == nil {
		state.Clients = map[string]OAuthClient{}
	}
	if state.Codes == nil {
		state.Codes = map[string]AuthCode{}
	}
	if state.Tokens == nil {
		state.Tokens = map[string]AccessToken{}
	}
	if state.RefreshTokens == nil {
		state.RefreshTokens = map[string]RefreshToken{}
	}
}

func (s *Store) view(fn func(State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.state)
}

func (s *Store) update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := cloneState(s.state)
	if err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	normalizeState(&next)
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func cloneState(src State) (State, error) {
	data, err := json.Marshal(src)
	if err != nil {
		return State{}, err
	}
	var dst State
	if err := json.Unmarshal(data, &dst); err != nil {
		return State{}, err
	}
	normalizeState(&dst)
	return dst, nil
}

func (s *Store) saveLocked(state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create state file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) encryptSecret(plain []byte) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte("ssh-hub:ssh-key:v1"))
	return base64.RawStdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (s *Store) decryptSecret(encoded string) ([]byte, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("encrypted key is truncated")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte("ssh-hub:ssh-key:v1"))
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func createPasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	const iterations = 260000
	derived := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.SplitN(encoded, "$", 4)
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100000 || iterations > 1000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return hmac.Equal(got, want)
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	result := make([]byte, 0, keyLength)
	for block := uint32(1); len(result) < keyLength; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], block)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		acc := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range acc {
				acc[j] ^= u[j]
			}
		}
		result = append(result, acc...)
	}
	return result[:keyLength]
}
