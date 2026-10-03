package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "login" || os.Args[1] == "mcp") {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err := runClientCommand(ctx, os.Args[1:]); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h":
			fmt.Println("Usage: ssh-hub [serve] | login --url URL [--profile NAME] [--force] | mcp --url URL [--profile NAME]")
			return
		case "--version":
			fmt.Println("ssh-hub 0.2.0")
			return
		case "serve":
		default:
			log.Fatalf("unknown command %q; use --help", os.Args[1])
		}
	}
	dataDir := envOr("SSHHUB_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("create data directory: %v", err)
	}
	store, err := openStore(dataDir)
	if err != nil {
		log.Fatalf("open data store: %v", err)
	}
	publicURL := strings.TrimRight(envOr("SSHHUB_PUBLIC_URL", "http://localhost:8080"), "/")
	if err := validatePublicURL(publicURL); err != nil {
		log.Fatalf("invalid SSHHUB_PUBLIC_URL: %v", err)
	}
	if err := migrateClientPolicies(store); err != nil {
		log.Fatalf("migrate client permissions: %v", err)
	}
	app := newApp(store, publicURL)
	app.keysDir = envOr("SSHHUB_KEYS_DIR", "/keys")
	if err := app.recoverAuditSessions(); err != nil {
		log.Fatalf("recover audit sessions: %v", err)
	}
	if adminURL := strings.TrimRight(os.Getenv("SSHHUB_ADMIN_URL"), "/"); adminURL != "" {
		if err := validatePublicURL(adminURL); err != nil {
			log.Fatalf("invalid SSHHUB_ADMIN_URL: %v", err)
		}
		app.adminURL = adminURL
	}
	if err := app.configureOIDC(oidcSettingsFromEnv()); err != nil {
		log.Fatalf("configure third-party identity provider: %v", err)
	}
	if password := os.Getenv("SSHHUB_ADMIN_PASSWORD"); password != "" {
		if err := app.setInitialPassword(password); err != nil {
			log.Fatalf("initialize administrator password: %v", err)
		}
	} else if token := app.setupToken(); token != "" {
		setupURL := publicURL
		if app.adminURL != "" {
			setupURL = app.adminURL
		}
		log.Printf("First run: open %s/login and enter this one-time setup token: %s", setupURL, token)
	}

	addr := envOr("SSHHUB_LISTEN_ADDR", ":8080")
	server := &http.Server{
		Addr:              addr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		WriteTimeout:      310 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("ssh-hub listening on %s (public URL %s)", addr, publicURL)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
