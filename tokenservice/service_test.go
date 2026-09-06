package tokenservice

import (
	"encoding/base64"
	"encoding/binary"
	"net/url"
	"strings"
	"testing"
	"time"

	common_globals "github.com/PretendoNetwork/nex-protocols-common-go/v2/globals"
)

var testAESKey = []byte("0123456789abcdef0123456789abcdef")

func TestIssueTokenRoundTrip(t *testing.T) {
	const pid = uint32(1768140980)
	const titleID = uint64(0x0005000010144e00)

	encoded, err := issueToken(testAESKey, pid, titleID, 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken returned an error: %v", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}

	decoded, nexError := common_globals.DecryptToken(encrypted, testAESKey)
	if nexError != nil {
		t.Fatalf("DecryptToken rejected issued token: %v", nexError)
	}
	if decoded.TokenType != 3 || decoded.UserPID != pid || decoded.TitleID != titleID {
		t.Fatalf("unexpected token: %+v", decoded)
	}
	if decoded.ExpireTime <= uint64(time.Now().UnixMilli()) {
		t.Fatalf("issued token is already expired")
	}
}

func TestIssueServiceTokenFormat(t *testing.T) {
	issued := time.UnixMilli(1700000000000)
	expires := issued.Add(24 * time.Hour)
	token, err := issueServiceToken(testAESKey, 1768140980, 0x0005000010144e00, issued, expires)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 60 {
		t.Fatalf("expected 60-byte service token, got %d", len(raw))
	}
	if got := binary.BigEndian.Uint32(raw[:4]); got != 1768140980 {
		t.Fatalf("unexpected PID: %d", got)
	}
	if got := binary.BigEndian.Uint64(raw[4:12]); got != 0x0005000010144e00 {
		t.Fatalf("unexpected title ID: %x", got)
	}
}

func TestPasswordFromPIDIsStableAndKeyed(t *testing.T) {
	secret := []byte("this-is-a-32-byte-long-secret!!!!")
	a, ok := passwordFromPID(secret, 1768140980)
	if !ok || a == "" {
		t.Fatalf("passwordFromPID failed: ok=%v pw=%q", ok, a)
	}
	if b, _ := passwordFromPID(secret, 1768140980); a != b {
		t.Fatalf("passwordFromPID is not stable: %q != %q", a, b)
	}
	if c, _ := passwordFromPID(secret, 1); a == c {
		t.Fatalf("passwordFromPID collides across PIDs")
	}
	if _, ok := passwordFromPID([]byte("too short"), 1); ok {
		t.Fatalf("passwordFromPID accepted a short secret")
	}
}

func baseTestConfig() Config {
	upstream, _ := url.Parse("https://account.pretendo.cc")
	return Config{
		Upstream:       upstream,
		GameServers:    map[string]GameServerConfig{"1012f100": {Host: "nex.example.test", AuthPort: 25000}},
		AESKey:         testAESKey,
		PasswordSecret: []byte("this-is-a-32-byte-long-secret!!!!"),
	}
}

func TestNewRequiresClientCertificatePair(t *testing.T) {
	config := baseTestConfig()
	config.ClientCertFile = "client-cert.pem"
	if _, err := New(config); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("expected a client certificate pair error, got %v", err)
	}
}

func TestNewRejectsBadKeyLengths(t *testing.T) {
	config := baseTestConfig()
	config.AESKey = []byte("short")
	if _, err := New(config); err == nil {
		t.Fatal("expected an AES key length error")
	}
	config = baseTestConfig()
	config.PasswordSecret = []byte("short")
	if _, err := New(config); err == nil {
		t.Fatal("expected a password secret length error")
	}
}

func TestParsePNIDProfile(t *testing.T) {
	pid, err := parsePNIDProfile([]byte(`<?xml version="1.0"?><person><user_id>tester</user_id><pid>1768140980</pid></person>`))
	if err != nil {
		t.Fatalf("parsePNIDProfile returned an error: %v", err)
	}
	if pid != 1768140980 {
		t.Fatalf("unexpected PID: %d", pid)
	}

	if _, err := parsePNIDProfile([]byte(`<?xml version="1.0"?><errors><error><code>1021</code></error></errors>`)); err == nil {
		t.Fatal("expected an error for a Pretendo error response")
	}
}
