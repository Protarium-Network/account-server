// Package tokenservice implements the Protarium account server: a reverse proxy
// in front of a real Nintendo Network Account System (NNAS) implementation that
// transparently forwards every request upstream except the NEX token and
// service token exchanges, which it answers itself with credentials that are
// only valid on the operator's own NEX servers.
//
// The console still authenticates against the upstream account provider (default
// https://account.pretendo.cc) for its PNID; this server only re-points the
// matchmaking handshake at self-hosted game servers.
package tokenservice

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
	"github.com/PretendoNetwork/plogger-go"
)

// Logger is used for all request logging. main() may replace it.
var Logger = plogger.NewLogger()

// GameServerConfig is one entry in Config.GameServers: the NEX authentication
// server a given game_server_id should be pointed at, plus an optional title-ID
// allowlist. An empty AllowedTitles means "any title" - appropriate for
// single-title game servers where the game_server_id match is gate enough.
type GameServerConfig struct {
	Host          string
	AuthPort      uint16
	AllowedTitles map[string]struct{}
}

// Config is the immutable configuration passed to New.
type Config struct {
	// Upstream is the real NNAS provider every non-intercepted request is
	// proxied to. Must be an https URL.
	Upstream *url.URL
	// GameServers maps a lowercase hex game_server_id to the NEX auth server
	// that should handle it.
	GameServers map[string]GameServerConfig
	// AESKey is the 32-byte AES-256 key used to sign NEX tokens. It must match
	// the key the target NEX servers validate with.
	AESKey []byte
	// PasswordSecret is the HMAC secret (>= 32 bytes) used to derive the stable
	// per-PID NEX password. It must match the secret the target NEX servers use.
	PasswordSecret []byte
	// ServiceTokenClientIDs is the set of lowercase client_id values allowed to
	// receive a locally signed service token.
	ServiceTokenClientIDs map[string]struct{}
	// TokenTTL is how long an issued NEX token stays valid. Default 15m.
	TokenTTL time.Duration
	// RequestTimeout bounds upstream profile lookups. Default 10s.
	RequestTimeout time.Duration
	// ClientCertFile / ClientKeyFile are an optional PEM client certificate the
	// proxy presents to the upstream. Some upstreams (Pretendo behind
	// Cloudflare) gate Wii U traffic on a console mTLS certificate. Set both or
	// neither.
	ClientCertFile string
	ClientKeyFile  string
}

type Service struct {
	config Config
	proxy  *httputil.ReverseProxy
	client *http.Client
}

type nexTokenXML struct {
	XMLName     xml.Name `xml:"nex_token"`
	Host        string   `xml:"host"`
	NEXPassword string   `xml:"nex_password"`
	PID         uint32   `xml:"pid"`
	Port        uint16   `xml:"port"`
	Token       string   `xml:"token"`
}

type pnidProfileXML struct {
	XMLName xml.Name `xml:"person"`
	PID     uint32   `xml:"pid"`
}

type serviceTokenXML struct {
	XMLName xml.Name `xml:"service_token"`
	Token   string   `xml:"token"`
}

// New validates config and builds the reverse proxy.
func New(config Config) (*Service, error) {
	if config.Upstream == nil || config.Upstream.Scheme != "https" {
		return nil, errors.New("account upstream must be an HTTPS URL")
	}
	if len(config.GameServers) == 0 {
		return nil, errors.New("at least one game server is required")
	}
	for id, gs := range config.GameServers {
		if gs.Host == "" || gs.AuthPort == 0 {
			return nil, fmt.Errorf("game server %q: host and auth port are required", id)
		}
	}
	if len(config.AESKey) != 32 {
		return nil, errors.New("NEX token AES key must contain exactly 32 bytes")
	}
	if len(config.PasswordSecret) < 32 {
		return nil, errors.New("NEX password secret must contain at least 32 bytes")
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 15 * time.Minute
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if (config.ClientCertFile == "") != (config.ClientKeyFile == "") {
		return nil, errors.New("upstream client certificate and key must be configured together")
	}
	if config.ClientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load upstream client certificate: %w", err)
		}
		// Cloudflare's Wii U mTLS gate currently validates the console
		// certificate on HTTP/1.1, but returns the generic browser-block page
		// when the same certificate is presented over HTTP/2.
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		transport.TLSClientConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{certificate},
		}
		Logger.Success("[ACCOUNT] Client certificate loaded for upstream (HTTP/1.1)")
	}

	proxy := httputil.NewSingleHostReverseProxy(config.Upstream)
	proxy.Transport = transport
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = config.Upstream.Host
		request.Header.Del("X-Forwarded-For")
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		request := response.Request
		Logger.Infof(
			"[ACCOUNT] upstream %s %s -> HTTP %d (server=%q, cf-ray=%q, ua=%q)",
			request.Method, request.URL.Path, response.StatusCode,
			response.Header.Get("Server"), response.Header.Get("CF-Ray"),
			request.Header.Get("User-Agent"),
		)
		return nil
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		Logger.Errorf(
			"[ACCOUNT] upstream proxy failed for %s %s (ua=%q): %v",
			request.Method, request.URL.Path, request.Header.Get("User-Agent"), err,
		)
		http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
	}

	return &Service{
		config: config,
		proxy:  proxy,
		client: &http.Client{Timeout: config.RequestTimeout, Transport: transport},
	}, nil
}

// ServeHTTP transparently proxies every Account request to the upstream except
// the NEX token and service token exchanges, which are re-signed for this
// operator's own NEX servers.
func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	Logger.Infof(
		"[ACCOUNT] Wii U %s %s?%s (title=%q, ua=%q)",
		request.Method, request.URL.Path, request.URL.RawQuery,
		request.Header.Get("X-Nintendo-Title-ID"), request.Header.Get("User-Agent"),
	)

	if request.URL.Path == "/v1/api/provider/service_token/@me" {
		service.handleServiceToken(writer, request)
		return
	}

	requestedGameServerID := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("game_server_id")))
	gameServer, isNexTokenRequest := service.config.GameServers[requestedGameServerID]
	if request.URL.Path != "/v1/api/provider/nex_token/@me" || !isNexTokenRequest {
		service.proxy.ServeHTTP(writer, request)
		return
	}

	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	titleID := strings.ToLower(strings.TrimPrefix(request.Header.Get("X-Nintendo-Title-ID"), "0x"))
	if len(gameServer.AllowedTitles) > 0 {
		if _, allowed := gameServer.AllowedTitles[titleID]; !allowed {
			Logger.Warningf(
				"[TOKEN] Rejected nex_token request: title %q is not allowed for game_server_id=%s",
				titleID, requestedGameServerID,
			)
			http.Error(writer, "title not allowed", http.StatusForbidden)
			return
		}
	}

	pid, status, body, err := service.fetchPNIDProfile(request)
	if err != nil {
		if status != 0 && len(body) > 0 {
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
		} else {
			Logger.Errorf("[TOKEN] upstream profile verification failed: %v", err)
			http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
		}
		return
	}

	password, ok := passwordFromPID(service.config.PasswordSecret, pid)
	if !ok {
		http.Error(writer, "credential service unavailable", http.StatusInternalServerError)
		return
	}

	token, err := issueToken(service.config.AESKey, pid, parseTitleID(titleID), service.config.TokenTTL)
	if err != nil {
		Logger.Errorf("[TOKEN] token generation failed: %v", err)
		http.Error(writer, "token generation failed", http.StatusInternalServerError)
		return
	}

	output, err := xml.Marshal(nexTokenXML{
		Host:        gameServer.Host,
		NEXPassword: password,
		PID:         pid,
		Port:        gameServer.AuthPort,
		Token:       token,
	})
	if err != nil {
		http.Error(writer, "token serialization failed", http.StatusInternalServerError)
		return
	}

	Logger.Successf(
		"[TOKEN] NEX token issued for PID=%d, game_server_id=%s, auth=%s:%d",
		pid, requestedGameServerID, gameServer.Host, gameServer.AuthPort,
	)
	writer.Header().Set("Content-Type", "text/xml; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Nintendo-Date", strconv.FormatInt(time.Now().UnixMilli(), 10))
	_, _ = writer.Write(output)
}

func (service *Service) handleServiceToken(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("client_id")))
	if clientID == "" {
		http.Error(writer, "client_id is required", http.StatusBadRequest)
		return
	}
	if _, allowed := service.config.ServiceTokenClientIDs[clientID]; !allowed {
		Logger.Warningf("[SERVICE-TOKEN] Rejected client_id=%q", clientID)
		http.Error(writer, "requested game server was not found", http.StatusNotFound)
		return
	}

	// The client_id selects the game server; the title is still required and is
	// signed into the token, but no per-title allowlist is applied here.
	titleID := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(request.Header.Get("X-Nintendo-Title-ID")), "0x"))
	if titleID == "" {
		http.Error(writer, "X-Nintendo-Title-ID is required", http.StatusBadRequest)
		return
	}

	pid, status, body, err := service.fetchPNIDProfile(request)
	if err != nil {
		if status != 0 && len(body) > 0 {
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
		} else {
			http.Error(writer, "upstream account service unavailable", http.StatusBadGateway)
		}
		return
	}

	issued := time.Now()
	expires := issued.Add(24 * time.Hour)
	token, err := issueServiceToken(service.config.AESKey, pid, parseTitleID(titleID), issued, expires)
	if err != nil {
		http.Error(writer, "service token generation failed", http.StatusInternalServerError)
		return
	}

	output, err := xml.Marshal(serviceTokenXML{Token: token})
	if err != nil {
		http.Error(writer, "service token serialization failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/xml; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(output)
	Logger.Successf("[SERVICE-TOKEN] Issued token for PID=%d client_id=%s", pid, clientID)
}

// fetchPNIDProfile calls the upstream /v1/api/people/@me/profile with the
// console's own credentials to confirm the PNID before issuing a local token.
func (service *Service) fetchPNIDProfile(request *http.Request) (uint32, int, []byte, error) {
	upstreamRequest := request.Clone(request.Context())
	upstreamRequest.URL.Scheme = service.config.Upstream.Scheme
	upstreamRequest.URL.Host = service.config.Upstream.Host
	upstreamRequest.URL.Path = "/v1/api/people/@me/profile"
	upstreamRequest.URL.RawPath = ""
	upstreamRequest.URL.RawQuery = ""
	upstreamRequest.Host = service.config.Upstream.Host
	upstreamRequest.RequestURI = ""
	upstreamRequest.Header.Del("X-Forwarded-For")

	response, err := service.client.Do(upstreamRequest)
	if err != nil {
		return 0, 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, response.StatusCode, body, err
	}
	if response.StatusCode != http.StatusOK {
		return 0, response.StatusCode, body, fmt.Errorf("profile rejected with HTTP %d", response.StatusCode)
	}
	pid, err := parsePNIDProfile(body)
	return pid, response.StatusCode, body, err
}

func parsePNIDProfile(body []byte) (uint32, error) {
	var profile pnidProfileXML
	if err := xml.Unmarshal(body, &profile); err != nil {
		return 0, err
	}
	if profile.XMLName.Local != "person" || profile.PID == 0 {
		return 0, errors.New("profile does not contain a valid PID")
	}
	return profile.PID, nil
}

// passwordFromPID derives the stable per-PID NEX password. The account endpoint
// and the NEX auth server independently derive the same secret from
// PasswordSecret, so no credential is ever stored.
func passwordFromPID(secret []byte, pid uint32) (string, bool) {
	if len(secret) < 32 {
		return "", false
	}
	pidBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(pidBytes, uint64(pid))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(pidBytes)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), true
}

// issueToken produces a Pretendo-format NEX token (AES-256-CBC, zero IV, PKCS#7
// padding, CRC32 of the plaintext prepended) as consumed by nex-go's
// ValidatePretendoLoginData.
func issueToken(key []byte, pid uint32, titleID uint64, ttl time.Duration) (string, error) {
	token := common_globals.NEXToken{
		SystemType:  1,
		TokenType:   3,
		UserPID:     pid,
		ExpireTime:  uint64(time.Now().Add(ttl).UnixMilli()),
		TitleID:     titleID,
		AccessLevel: 0,
	}

	var plain bytes.Buffer
	if err := binary.Write(&plain, binary.LittleEndian, token); err != nil {
		return "", err
	}

	padding := aes.BlockSize - plain.Len()%aes.BlockSize
	plain.Write(bytes.Repeat([]byte{byte(padding)}, padding))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	encrypted := make([]byte, plain.Len())
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(encrypted, plain.Bytes())

	result := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(result[:4], crc32.ChecksumIEEE(plain.Bytes()[:plain.Len()-padding]))
	copy(result[4:], encrypted)
	return base64.StdEncoding.EncodeToString(result), nil
}

// issueServiceToken produces the 60-byte HMAC-SHA256 service token:
// pid(4) | titleID(8) | issued_ms(8) | expires_ms(8) | mac(32), all big-endian.
func issueServiceToken(key []byte, pid uint32, titleID uint64, issued, expires time.Time) (string, error) {
	data := make([]byte, 28)
	binary.BigEndian.PutUint32(data[0:4], pid)
	binary.BigEndian.PutUint64(data[4:12], titleID)
	binary.BigEndian.PutUint64(data[12:20], uint64(issued.UnixMilli()))
	binary.BigEndian.PutUint64(data[20:28], uint64(expires.UnixMilli()))

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return base64.StdEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

// DecodeHexSecret parses a hex-encoded secret and checks its decoded length.
func DecodeHexSecret(value string, expected int) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != expected {
		return nil, fmt.Errorf("secret must be %d bytes encoded as hexadecimal", expected)
	}
	return decoded, nil
}

func parseTitleID(value string) uint64 {
	titleID, _ := strconv.ParseUint(value, 16, 64)
	return titleID
}
