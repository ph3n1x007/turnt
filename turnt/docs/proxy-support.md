# Proxy Support for turnt-relay

## Overview

This document covers the proxy support added to `turnt-relay`, enabling it to establish WebRTC/TURN connections through HTTP CONNECT proxies with automatic Kerberos (SPNEGO/Negotiate) authentication via Windows SSPI.

## Problem

In corporate environments, outbound network traffic is routed through authenticated HTTP proxies. The relay's TURN TCP connections to the signaling infrastructure are blocked unless they go through the proxy. Windows endpoints are the primary deployment target, and these environments typically use Kerberos authentication tied to the user's Active Directory domain session.

## Usage

```
# Explicit proxy
./relay.exe -offer "<payload>" -proxy http://proxy.corp.local:8080

# Explicit proxy with basic auth credentials
./relay.exe -offer "<payload>" -proxy http://user:pass@proxy.corp.local:8080

# Auto-detect proxy from environment/system settings
./relay.exe -offer "<payload>" -proxy auto

# No proxy (unchanged behavior)
./relay.exe -offer "<payload>"
```

### Auto-detection order (`-proxy auto`)

1. Environment variables: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`
2. Windows only: registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable` + `ProxyServer`)

## Architecture

### New package: `internal/proxy/`

```
internal/proxy/
├── dialer.go               # HTTP CONNECT dialer (cross-platform)
├── detect.go               # Proxy auto-detection (env vars + platform dispatch)
├── detect_windows.go       # Windows registry proxy detection
├── detect_other.go         # Non-Windows stub
├── negotiate_windows.go    # Windows SSPI Kerberos/Negotiate auth
└── negotiate_other.go      # Non-Windows stub (returns error)
```

### Modified files

| File | Change |
|------|--------|
| `internal/webrtc/handshake.go` | `NewPeerConnection` accepts an optional `proxy.Dialer` parameter, passed to pion via `SetICEProxyDialer` |
| `cmd/relay/relay.go` | New `--proxy` flag, proxy initialization logic before peer connection creation |
| `cmd/controller/controller.go` | Updated `NewPeerConnection` call to pass `nil` (controller doesn't need proxy) |

## Design Choices

### Why HTTP CONNECT (not SOCKS)

Corporate proxies are overwhelmingly HTTP proxies. SOCKS proxies are rare in enterprise environments and don't use Kerberos authentication. HTTP CONNECT is the standard method for tunneling arbitrary TCP through an HTTP proxy — the proxy establishes a TCP tunnel after the CONNECT handshake, and all subsequent bytes pass through transparently. This is exactly what TURN-over-TCP needs.

### Why pion's `SetICEProxyDialer`

Pion/webrtc v3.3.5 exposes `SettingEngine.SetICEProxyDialer(proxy.Dialer)`, which injects a custom dialer into the ICE agent. When pion needs to connect to a TURN server over TCP, it calls our dialer instead of `net.Dial`. This is the cleanest integration point because:

- No patching of pion internals
- No local listener/port-forwarding hacks
- Works with pion's existing TURN client, ICE candidate gathering, and connection lifecycle
- The `proxy.Dialer` interface (`Dial(network, addr string) (net.Conn, error)`) is a single method — minimal surface area

The relay already restricts to TCP-only network types (`NetworkTypeTCP4`, `NetworkTypeTCP6`) and relay-only transport policy (`ICETransportPolicyRelay`), so all ICE traffic is TURN-over-TCP, which tunnels cleanly through HTTP CONNECT.

### Why Windows SSPI (not a Go Kerberos library)

Two options existed for Kerberos authentication:

1. **Pure Go Kerberos** (e.g., `gokrb5`): Requires explicit configuration — krb5.conf, keytab files, or credential cache paths. Works cross-platform but doesn't integrate with the Windows login session.

2. **Windows SSPI** (`secur32.dll`): Uses the logged-in user's domain credentials automatically. No configuration needed — if the user is logged into a domain-joined machine, SSPI produces valid Kerberos tickets transparently.

SSPI was chosen because:

- The relay runs on Windows endpoints in domain-joined environments. The user's existing Kerberos TGT from their Windows login session is exactly what the proxy expects.
- Zero configuration: no keytabs, no krb5.conf, no credential prompts.
- SSPI's "Negotiate" package automatically handles protocol selection — it uses Kerberos when available and falls back to NTLM when it isn't (e.g., non-domain proxy, cross-forest scenarios).
- No CGO: the implementation uses `syscall.NewLazyDLL` to load `secur32.dll` at runtime, so it cross-compiles from Linux with `GOOS=windows`.

### SSPI implementation details

The Negotiate authentication flow with a proxy:

```
Client                          Proxy
  |--- CONNECT host:port -------->|
  |<-- 407 Proxy-Authenticate: Negotiate --|
  |                                        |
  | [SSPI: AcquireCredentialsHandle("Negotiate")]
  | [SSPI: InitializeSecurityContext() -> token]
  |                                        |
  |--- CONNECT host:port -------->|
  |    Proxy-Authorization: Negotiate <token>
  |<-- 200 Connection Established --|  (Kerberos: single round)
```

If SSPI selects NTLM instead of Kerberos (fallback), the proxy responds with a challenge token and a second `InitializeSecurityContext` call completes the handshake. The implementation supports up to 5 rounds to cover both protocols.

Key SSPI structures mapped to Go:

```go
type secHandle struct {    // CredHandle / CtxtHandle
    Lower uintptr          // ULONG_PTR — 4 bytes on 386, 8 bytes on amd64/arm64
    Upper uintptr
}

type secBuffer struct {
    Size   uint32          // unsigned long (Win LLP64: always 4 bytes)
    Type   uint32
    Buffer uintptr         // void* — matches pointer size
}

type secBufferDesc struct {
    Version uint32
    Count   uint32
    Buffers *secBuffer
}
```

These layouts are correct on all three Windows architectures (386, amd64, arm64) because Go's `uintptr` and pointer types naturally match the platform's pointer size, and `uint32` matches Windows `unsigned long` (4 bytes on all Windows platforms due to LLP64).

`runtime.KeepAlive` calls prevent the GC from collecting Go-allocated buffers that are referenced only via `uintptr` in the SSPI structs during the syscall.

The SPN (Service Principal Name) used for Kerberos is `HTTP/<proxy-hostname>`, which is the standard SPN format for HTTP proxy services registered in Active Directory.

### Why build tags (not runtime detection)

The Windows-specific code (`negotiate_windows.go`, `detect_windows.go`) uses `//go:build windows` tags rather than runtime `GOOS` checks because:

- `secur32.dll` and `golang.org/x/sys/windows/registry` don't exist on other platforms — they can't compile
- Build tags exclude the files entirely during compilation, producing zero overhead on non-Windows binaries
- The non-Windows stubs (`negotiate_other.go`, `detect_other.go`) provide clear error messages when someone attempts Negotiate auth on Linux/macOS

### Why the dialer handles auth negotiation inline

The `HTTPConnectDialer.Dial` method handles the full auth negotiation (initial CONNECT → 407 → retry with credentials) within a single call. An alternative would have been to pre-authenticate or cache tokens, but:

- TURN connections are infrequent (typically one per session). The overhead of an extra round-trip for the 407 probe is negligible.
- Probing first lets the dialer adapt: if the proxy doesn't require auth, no SSPI calls are made. If it requires Basic instead of Negotiate, that works too.
- Connection reuse between the 407 and the authenticated retry avoids a second TCP handshake in the common case (HTTP/1.1 keep-alive).

### Why the controller wasn't modified for proxy

The controller runs on the operator's machine (not behind a corporate proxy), so it doesn't need proxy support. Its `NewPeerConnection` call passes `nil` for the proxy dialer, preserving existing behavior with no overhead.

### No new dependencies

The implementation uses only packages already in the module graph:

- `golang.org/x/net/proxy` — already a direct dependency (part of `golang.org/x/net v0.22.0`)
- `golang.org/x/sys/windows/registry` — already an indirect dependency (`golang.org/x/sys v0.18.0`)
- `syscall`, `unsafe`, `runtime` — standard library

No new third-party modules were added.

## Error messages

Common failure scenarios produce actionable messages:

| Scenario | Message |
|----------|---------|
| Proxy unreachable | `failed to connect to proxy proxy:8080: connection refused` |
| Proxy rejects without auth challenge | `proxy returned unexpected status: 403 Forbidden` |
| No domain credentials (not logged in with AD account) | `SSPI InitializeSecurityContext failed: no credentials available (not logged in with a domain account?)` |
| Proxy hostname not in AD/DNS for SPN | `SSPI InitializeSecurityContext failed: target unknown (proxy hostname not resolvable via Kerberos?)` |
| Auth succeeds but tunnel rejected | `proxy Negotiate auth failed: 403 Forbidden` |
| Auto-detect finds nothing | `No proxy detected from system/environment` |
| Negotiate auth attempted on Linux/macOS | `Negotiate/Kerberos proxy authentication requires Windows (SSPI)` |

## Testing

Since this involves Windows SSPI and corporate proxy infrastructure, automated testing is limited. Manual verification:

1. **No proxy (regression)**: `./relay.exe -offer <payload>` — should behave identically to before.
2. **Explicit proxy, no auth**: `./relay.exe -offer <payload> -proxy http://squid:3128` with an open proxy.
3. **Explicit proxy, Kerberos**: `./relay.exe -offer <payload> -proxy http://proxy.corp.local:8080` on a domain-joined machine behind a Negotiate-authenticated proxy.
4. **Auto-detect**: Set `HTTPS_PROXY=http://proxy:8080` or configure Windows Internet Settings, then `./relay.exe -offer <payload> -proxy auto`.
5. **Cross-compile**: `GOOS=windows GOARCH=amd64 go build ./cmd/relay/` from Linux — verified, compiles clean.
6. **`go vet`**: Passes on both `GOOS=linux` and `GOOS=windows`.
