package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type clientCredentials struct {
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type hubClient struct {
	origin, profile, credentialsPath string
	http                             *http.Client
}
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func newHubClient(origin, profile string) (*hubClient, error) {
	origin = strings.TrimRight(origin, "/")
	origin = strings.TrimSuffix(origin, "/mcp")
	if err := validatePublicURL(origin); err != nil {
		return nil, err
	}
	if profile == "" || len(profile) > 64 {
		return nil, errors.New("profile must contain 1–64 characters")
	}
	dir := os.Getenv("SSHHUB_CREDENTIALS_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "ssh-hub")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &hubClient{origin: origin, profile: profile, credentialsPath: filepath.Join(dir, tokenDigest(origin+"\n"+profile)+".json"), http: &http.Client{Timeout: 320 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *hubClient) requestJSON(ctx context.Context, path, contentType string, body io.Reader, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(out)
	return resp.StatusCode, err
}

func (c *hubClient) saveCredentials(creds clientCredentials) error {
	f, err := os.CreateTemp(filepath.Dir(c.credentialsPath), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(creds)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), c.credentialsPath)
}

func (c *hubClient) credentials(ctx context.Context, interactive, force bool) (clientCredentials, error) {
	// Serialize refresh-token rotation between Agent processes using one profile.
	lock, err := os.OpenFile(c.credentialsPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return clientCredentials{}, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return clientCredentials{}, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var creds clientCredentials
	data, err := os.ReadFile(c.credentialsPath)
	if err != nil && !os.IsNotExist(err) {
		return creds, err
	}
	if len(data) > 0 {
		if err = json.Unmarshal(data, &creds); err != nil {
			return creds, errors.New("invalid credentials file")
		}
	}
	if !force && creds.AccessToken != "" && time.Now().Add(time.Minute).Before(creds.ExpiresAt) {
		return creds, nil
	}
	if !force && creds.RefreshToken != "" {
		var result tokenResponse
		status, err := c.requestJSON(ctx, "/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "client_id": {creds.ClientID}, "refresh_token": {creds.RefreshToken}, "resource": {c.origin + "/mcp"}}.Encode()), &result)
		if err != nil {
			return creds, err
		}
		if status == 200 && result.AccessToken != "" && result.RefreshToken != "" {
			creds.AccessToken, creds.RefreshToken, creds.ExpiresAt = result.AccessToken, result.RefreshToken, time.Now().Add(time.Duration(result.ExpiresIn)*time.Second)
			return creds, c.saveCredentials(creds)
		}
		if result.Error != "invalid_grant" {
			return creds, fmt.Errorf("refresh failed: HTTP %d %s", status, result.Error)
		}
	}
	if !interactive {
		return creds, errors.New("login required: run ssh-hub login with the same --url and --profile first")
	}
	return c.deviceLogin(ctx, creds)
}

func (c *hubClient) deviceLogin(ctx context.Context, creds clientCredentials) (clientCredentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	register := func() error {
		host, _ := os.Hostname()
		body, _ := json.Marshal(map[string]any{"client_name": "SSH Hub " + c.profile + " @ " + host, "grant_types": []string{deviceGrantType, "refresh_token"}, "token_endpoint_auth_method": "none", "scope": "mcp"})
		var result struct {
			ClientID string `json:"client_id"`
			Error    string `json:"error"`
		}
		status, err := c.requestJSON(ctx, "/oauth/register", "application/json", bytes.NewReader(body), &result)
		if err != nil {
			return err
		}
		if status != 201 || result.ClientID == "" {
			return fmt.Errorf("registration failed: HTTP %d %s", status, result.Error)
		}
		creds = clientCredentials{ClientID: result.ClientID}
		return c.saveCredentials(creds)
	}
	if creds.ClientID == "" {
		if err := register(); err != nil {
			return creds, err
		}
	}
	var device struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_uri_complete"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	start := func() (int, error) {
		return c.requestJSON(ctx, "/oauth/device/code", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"client_id": {creds.ClientID}, "scope": {"mcp"}, "resource": {c.origin + "/mcp"}}.Encode()), &device)
	}
	status, err := start()
	if err == nil && device.Error == "invalid_client" {
		if err = register(); err == nil {
			device.Error = ""
			status, err = start()
		}
	}
	if err != nil {
		return creds, err
	}
	if status != 200 || device.DeviceCode == "" {
		return creds, fmt.Errorf("device authorization failed: HTTP %d %s", status, device.Error)
	}
	fmt.Fprintf(os.Stderr, "在自己的浏览器打开：\n%s\n核对设备码：%s\n等待确认；无需复制回调地址。\n", device.VerificationURL, device.UserCode)
	interval := time.Duration(device.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return creds, ctx.Err()
		case <-timer.C:
		}
		var result tokenResponse
		status, err := c.requestJSON(ctx, "/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"grant_type": {deviceGrantType}, "device_code": {device.DeviceCode}, "client_id": {creds.ClientID}, "resource": {c.origin + "/mcp"}}.Encode()), &result)
		if err != nil {
			interval *= 2
			continue
		}
		if status == 200 && result.AccessToken != "" {
			creds.AccessToken, creds.RefreshToken, creds.ExpiresAt = result.AccessToken, result.RefreshToken, time.Now().Add(time.Duration(result.ExpiresIn)*time.Second)
			if err := c.saveCredentials(creds); err != nil {
				return creds, err
			}
			fmt.Fprintln(os.Stderr, "登录成功。请在管理控制台为该客户端配置机器权限。")
			return creds, nil
		}
		switch result.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return creds, fmt.Errorf("device login failed: %s", result.Error)
		}
	}
}

func (c *hubClient) bridge(ctx context.Context, input io.Reader, output io.Writer) error {
	if _, err := c.credentials(ctx, false, false); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxMCPBody)
	version := defaultMCPVersion
	for scanner.Scan() {
		data := append([]byte(nil), scanner.Bytes()...)
		var rpc jsonRPCRequest
		if json.Unmarshal(data, &rpc) != nil || rpc.JSONRPC != "2.0" {
			return errors.New("invalid stdio JSON-RPC request")
		}
		failure := func(err error) {
			if len(rpc.ID) > 0 {
				_ = json.NewEncoder(output).Encode(jsonRPCResponse{JSONRPC: "2.0", ID: rpc.ID, Error: &jsonRPCError{Code: -32000, Message: err.Error() + "; execution was not retried"}})
			}
		}
		creds, err := c.credentials(ctx, false, false)
		if err != nil {
			failure(err)
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/mcp", bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", version)
		resp, err := c.http.Do(req)
		if err != nil {
			failure(errors.New("MCP transport failed; execution status may be unknown, check audit before resubmitting"))
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			failure(readErr)
			continue
		}
		if resp.StatusCode == 202 {
			continue
		}
		if resp.StatusCode != 200 {
			failure(fmt.Errorf("MCP HTTP %d; for 401 run ssh-hub login --force", resp.StatusCode))
			continue
		}
		if rpc.Method == "initialize" {
			var init struct {
				Result struct {
					Version string `json:"protocolVersion"`
				}
			}
			if json.Unmarshal(body, &init) == nil && init.Result.Version != "" {
				version = init.Result.Version
			}
		}
		if len(rpc.ID) > 0 {
			var compact bytes.Buffer
			if err := json.Compact(&compact, body); err != nil {
				failure(errors.New("invalid MCP response"))
				continue
			}
			if _, err = fmt.Fprintln(output, compact.String()); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func runClientCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	origin := flags.String("url", "", "SSH Hub HTTPS origin or /mcp URL")
	profile := flags.String("profile", "default", "separate OAuth client profile")
	force := flags.Bool("force", false, "request a new browser authorization")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *origin == "" {
		return errors.New("--url is required")
	}
	client, err := newHubClient(*origin, *profile)
	if err != nil {
		return err
	}
	if args[0] == "login" {
		_, err = client.credentials(ctx, true, *force)
		if err == nil {
			fmt.Fprintln(os.Stderr, "SSH Hub credentials are ready.")
		}
		return err
	}
	return client.bridge(ctx, os.Stdin, os.Stdout)
}
