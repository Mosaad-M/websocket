# CLAUDE.md — WebSocket Module

## Overview

A **native Mojo WebSocket client** (RFC 6455) — no Python interop. Built on top of the `tcp`, `tls`, and `url` modules using POSIX socket FFI and OpenSSL FFI for crypto (SHA-1, Base64, random bytes).

Supports `ws://` (plain TCP) and `wss://` (TLS) connections with text/binary messages, ping/pong, clean close handshake, and fragment reassembly.

## Architecture

```
websocket.mojo
  WebSocket struct        — connect, send_text, send_binary, recv, close
  WebSocketFrame struct   — decoded frame (fin, opcode, payload)
  Crypto helpers          — _sha1, _base64_encode, _rand_bytes (FFI)
  Protocol validation     — RSV, mask, UTF-8, close codes, CRLF, handshake
```

## Files

| File | Purpose |
|------|---------|
| `websocket.mojo` | WebSocket protocol implementation |
| `test_websocket.mojo` | 23 tests (8 functional + 15 security) |
| `test_ws_server.py` | Python test servers (echo on :18081, malicious on :18082) |
| `main.mojo` | Demo: connect to localhost echo server |
| `SECURITY_PLAN.md` | Security audit + 3-session hardening plan + progress log |

## Dependencies (symlinks)

```
tcp.mojo       -> ../tcp/tcp.mojo
tls.mojo       -> ../tls/tls.mojo
url.mojo       -> ../url/url.mojo
ssl_wrapper.c  -> ../tls/ssl_wrapper.c
.build_tools/  -> ../tls/.build_tools/
build_and_run.sh -> ../tls/build_and_run.sh
```

## Build & Run

```bash
pixi run compile-ssl     # Compile libssl_wrapper.so
pixi run test            # Run all 23 tests (needs test_ws_server.py running)
pixi run run             # Run demo
pixi run format          # Format .mojo files
```

### Running Tests

```bash
# Terminal 1: Start test servers
python3 test_ws_server.py

# Terminal 2: Run tests
pixi run test
```

## Security Features

All security features were added through a 3-session hardening process based on an audit against RFC 6455, OWASP, and known CVEs. See `SECURITY_PLAN.md` for full details.

### Memory Safety (DoS Prevention)
- **max_frame_size** (default 16 MB) — rejects frames exceeding this before allocation
- **max_message_size** (default 16 MB) — caps accumulated fragment size
- **max_send_size** (default 16 MB) — caps outbound payload size
- **Control frame size** — enforces 125-byte limit per RFC 6455 Section 5.5

### Protocol Compliance (RFC 6455)
- **RSV bits** — rejects non-zero RSV bits (no extensions negotiated)
- **Masked server frames** — rejects masked server-to-client frames
- **Fragmented control frames** — rejects control frames with FIN=0
- **Close code validation** — validates codes per Section 7.4.1 (1000-1003, 1007-1011, 3000-4999)
- **UTF-8 validation** — validates text frame payloads (overlong, surrogates, range)

### Handshake Hardening
- **CRLF injection prevention** — rejects `\r`/`\n` in request path
- **Strict status line parsing** — requires exact `HTTP/1.1 101`
- **Sec-WebSocket-Accept validation** — case-insensitive header match with computed value

### Network Security
- **SSRF protection** — `allow_private_ips = False` blocks 127.0.0.0/8, 10.0.0.0/8, etc.
- **Origin header** — optional `origin` field for CSWSH protection
- **Socket timeouts** — 30-second SO_RCVTIMEO/SO_SNDTIMEO (inherited from tcp module)

### Usage

```mojo
var ws = WebSocket()

# Configure security limits
ws.max_frame_size = 1024 * 1024       # 1 MB max frame
ws.max_message_size = 4 * 1024 * 1024 # 4 MB max message
ws.max_send_size = 1024 * 1024        # 1 MB max send

# SSRF protection
ws.allow_private_ips = False

# Origin header for CSWSH protection
ws.origin = "https://myapp.example.com"

ws.connect("wss://echo.example.com/ws")
ws.send_text("hello")
var frame = ws.recv()
print(frame.as_text())
ws.close()
```
