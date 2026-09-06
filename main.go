// Command account-server runs the Protarium account proxy / NEX token issuer.
//
// It sits behind a TLS-terminating reverse proxy that routes the console's
// account domain (e.g. account.example.org) to PN_ACCOUNT_HTTP_LISTEN. Every
// request is forwarded to PN_ACCOUNT_UPSTREAM unchanged except nex_token and
// service_token, which are re-signed for the operator's own NEX servers.
package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"net/http"
	"net/url"

	"github.com/PretendoNetwork/plogger-go"
	"github.com/joho/godotenv"

	"github.com/Protarium-Network/account-server/tokenservice"
)

var logger = plogger.NewLogger()

func main() {
	tokenservice.Logger = logger

	if err := godotenv.Load(); err != nil {
		logger.Warning("no .env file loaded; relying on the process environment")
	}

	upstream, err := url.Parse(envOrDefault("PN_ACCOUNT_UPSTREAM", "https://account.pretendo.cc"))
	if err != nil {
		logger.Criticalf("PN_ACCOUNT_UPSTREAM is not a valid URL: %v", err)
		os.Exit(1)
	}

	aesKey, err := tokenservice.DecodeHexSecret(os.Getenv("PN_NEX_TOKEN_AES_KEY"), 32)
	if err != nil {
		logger.Criticalf("PN_NEX_TOKEN_AES_KEY: %v (generate with: openssl rand -hex 32)", err)
		os.Exit(1)
	}
	passwordSecret, err := tokenservice.DecodeHexSecret(os.Getenv("PN_NEX_PASSWORD_SECRET"), 32)
	if err != nil {
		logger.Criticalf("PN_NEX_PASSWORD_SECRET: %v (generate with: openssl rand -hex 32)", err)
		os.Exit(1)
	}

	gameServers, err := parseGameServers(os.Getenv("PN_GAME_SERVERS"))
	if err != nil {
		logger.Criticalf("PN_GAME_SERVERS: %v", err)
		os.Exit(1)
	}
	if len(gameServers) == 0 {
		logger.Critical("PN_GAME_SERVERS is empty; nothing to route")
		os.Exit(1)
	}

	service, err := tokenservice.New(tokenservice.Config{
		Upstream:              upstream,
		GameServers:           gameServers,
		AESKey:                aesKey,
		PasswordSecret:        passwordSecret,
		ServiceTokenClientIDs: csvSet(os.Getenv("PN_SERVICE_TOKEN_CLIENT_IDS")),
		TokenTTL:              15 * time.Minute,
		RequestTimeout:        10 * time.Second,
		ClientCertFile:        strings.TrimSpace(os.Getenv("PN_ACCOUNT_CLIENT_CERT")),
		ClientKeyFile:         strings.TrimSpace(os.Getenv("PN_ACCOUNT_CLIENT_KEY")),
	})
	if err != nil {
		logger.Criticalf("configuration rejected: %v", err)
		os.Exit(1)
	}

	listenAddress := envOrDefault("PN_ACCOUNT_HTTP_LISTEN", ":8080")
	logger.Successf("account server listening on %s, %d game server(s) configured, upstream=%s",
		listenAddress, len(gameServers), upstream)
	if err := http.ListenAndServe(listenAddress, service); err != nil {
		logger.Criticalf("http server stopped: %v", err)
		os.Exit(1)
	}
}

// parseGameServers reads PN_GAME_SERVERS. Two accepted forms:
//
//   - JSON object keyed by lowercase hex game_server_id:
//     {"1012f100":{"host":"nex.example.org","auth_port":25000,"titles":["000500001012f100"]}}
//   - compact line/comma list, one entry per line or comma:
//     1012f100=nex.example.org:25000
//     1012f100=nex.example.org:25000:000500001012f100,0005000010144d00
//
// "titles" is optional; when omitted any title is accepted for that ID.
func parseGameServers(raw string) (map[string]tokenservice.GameServerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	if strings.HasPrefix(raw, "{") {
		var wire map[string]struct {
			Host     string   `json:"host"`
			AuthPort uint16   `json:"auth_port"`
			Titles   []string `json:"titles"`
		}
		if err := json.Unmarshal([]byte(raw), &wire); err != nil {
			return nil, err
		}
		out := make(map[string]tokenservice.GameServerConfig, len(wire))
		for id, entry := range wire {
			titles := make(map[string]struct{}, len(entry.Titles))
			for _, t := range entry.Titles {
				if t = normalizeHex(t); t != "" {
					titles[t] = struct{}{}
				}
			}
			out[strings.ToLower(strings.TrimSpace(id))] = tokenservice.GameServerConfig{
				Host: entry.Host, AuthPort: entry.AuthPort, AllowedTitles: titles,
			}
		}
		return out, nil
	}

	out := map[string]tokenservice.GameServerConfig{}
	// Entries are separated by newline or ';'. Each is id=host:port[:title,title].
	for _, entry := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == ';' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, rest, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, entryError(entry)
		}
		parts := strings.SplitN(strings.TrimSpace(rest), ":", 3)
		if len(parts) < 2 {
			return nil, entryError(entry)
		}
		port, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil {
			return nil, entryError(entry)
		}
		titles := map[string]struct{}{}
		if len(parts) == 3 {
			for _, t := range strings.Split(parts[2], ",") {
				if t = normalizeHex(t); t != "" {
					titles[t] = struct{}{}
				}
			}
		}
		out[normalizeHex(id)] = tokenservice.GameServerConfig{
			Host:          strings.TrimSpace(parts[0]),
			AuthPort:      uint16(port),
			AllowedTitles: titles,
		}
	}
	return out, nil
}

type entryError string

func (e entryError) Error() string {
	return "invalid entry " + strconv.Quote(string(e)) + " (want id=host:port[:title,title])"
}

func normalizeHex(v string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "0x"))
}

func csvSet(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range strings.Split(csv, ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

func envOrDefault(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
