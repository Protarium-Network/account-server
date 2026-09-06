# account-server

A thin account server for revived Wii U online services. It is a reverse proxy
in front of a real Nintendo Network Account System (NNAS) implementation
(Pretendo's `account.pretendo.cc` by default) that transparently forwards every
request **except** the matchmaking handshake, which it re-signs so the console
connects to your own NEX servers instead of the upstream's.

This is the account component of the [Protarium](https://github.com/Protarium-Network)
network, extracted to run on its own.

## What it does

The Wii U asks its account server for two things before joining a game's online
services:

| Request | Handled by |
| --- | --- |
| `GET /v1/api/provider/nex_token/@me?game_server_id=<id>` | **Intercepted** when `<id>` is configured: the console's PNID is verified against the upstream (`/v1/api/people/@me/profile`), then a NEX token + per-PID password for your own auth server are returned. |
| `GET /v1/api/provider/service_token/@me?client_id=<id>` | **Intercepted** when `<id>` is allowlisted: an HMAC-SHA256 service token is returned. |
| everything else (login, profile, PNID, Miiverse discovery, …) | **Proxied unchanged** to `PN_ACCOUNT_UPSTREAM`. |

The console still authenticates its PNID against the upstream. This server only
re-points the NEX handshake; it does not store accounts or credentials.

### Tokens

- **NEX token** — Pretendo wire format: AES-256-CBC (zero IV, PKCS#7), CRC32 of
  the plaintext prepended, base64. Validated by `nex-go`'s
  `ValidatePretendoLoginData` with `PN_NEX_TOKEN_AES_KEY`.
- **NEX password** — `base64url(HMAC-SHA256(PN_NEX_PASSWORD_SECRET, pid_le64))`.
  Stable per PID, so the account server and the NEX auth server derive the same
  value without storing anything.
- **Service token** — `pid(4) | titleID(8) | issued_ms(8) | expires_ms(8) |
  HMAC-SHA256(...)(32)`, big-endian, base64.

Both secrets **must** match the values your NEX servers are configured with.

## Configuration

All configuration is environment variables (a `.env` file is loaded if present).
See [`.env.example`](.env.example).

| Variable | Required | Notes |
| --- | --- | --- |
| `PN_ACCOUNT_HTTP_LISTEN` | no (`:8080`) | listen address |
| `PN_ACCOUNT_UPSTREAM` | no (`https://account.pretendo.cc`) | must be `https` |
| `PN_NEX_TOKEN_AES_KEY` | **yes** | 64 hex chars (`openssl rand -hex 32`) |
| `PN_NEX_PASSWORD_SECRET` | **yes** | 64 hex chars (`openssl rand -hex 32`) |
| `PN_GAME_SERVERS` | **yes** | routing table, see below |
| `PN_SERVICE_TOKEN_CLIENT_IDS` | no | comma-separated `client_id` allowlist; empty disables `service_token` |
| `PN_ACCOUNT_CLIENT_CERT` / `PN_ACCOUNT_CLIENT_KEY` | no | PEM client cert presented to the upstream (Pretendo behind Cloudflare gates Wii U traffic on the console common certificate). Set both or neither. |

### `PN_GAME_SERVERS`

One entry per line or `;`-separated:

```
<game_server_id>=<host>:<auth_port>[:<title_id>,<title_id>,...]
```

```
1012f100=nex.example.org:25000:000500001012f100,0005000010144d00
10190300=nex.example.org:25010
```

The optional title list restricts which `X-Nintendo-Title-ID` may use that
`game_server_id`. Omit it for single-title game servers. A JSON object form is
also accepted if the value starts with `{` — see `.env.example`.

## Running

```
cp .env.example .env      # then edit it
go run .
```

Or with Docker:

```
docker build -t account-server .
docker run --rm -p 8080:8080 --env-file .env account-server
```

TLS is expected to be terminated by a reverse proxy in front of this service
that routes your console account domain to `PN_ACCOUNT_HTTP_LISTEN`.

## Tests

```
go test ./...
```

## License

[AGPL-3.0](LICENSE), matching `nex-protocols-common-go`.
