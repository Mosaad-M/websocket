"""WebSocket echo server for testing.

Runs two servers:
- Port 18081: Normal echo server (echoes text/binary, handles ping/close)
- Port 18082: Malicious server for security tests (path-based behavior)

Malicious server paths:
- /masked-frame     — sends a masked server frame (violates RFC 6455)
- /rsv-bits         — sends a frame with RSV1 bit set
- /oversized-ping   — sends a ping with 200-byte payload (>125 limit)
- /fragmented-ping  — sends a ping with FIN=0 (fragmented control frame)
- /huge-payload     — declares a 1GB payload length (memory exhaustion)
- /invalid-close-code — sends close frame with code 999 (invalid)
- /close-code-1005 — sends close frame with reserved code 1005
- /invalid-utf8    — sends text frame with invalid UTF-8 bytes
- /bad-handshake-200 — responds with HTTP 200 instead of 101
- /bad-handshake-accept — responds with wrong Sec-WebSocket-Accept
"""

import socket
import struct
import hashlib
import base64
import threading
import sys

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def handle_client(conn, addr, malicious=False):
    """Handle a single WebSocket client."""
    try:
        # Read HTTP upgrade request
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        # Extract request path and Sec-WebSocket-Key
        first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
        path = first_line.split(" ")[1] if " " in first_line else "/"

        key = None
        for line in data.decode("utf-8", errors="replace").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
                break

        if not key:
            conn.close()
            return

        # Compute accept key
        accept = base64.b64encode(
            hashlib.sha1(key.encode() + WS_MAGIC).digest()
        ).decode()

        # For malicious server, check if path needs a bad handshake
        if malicious and path == "/bad-handshake-200":
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "\r\n"
            )
            conn.sendall(response.encode())
            return
        elif malicious and path == "/bad-handshake-accept":
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: WRONGACCEPTVALUE==\r\n"
                "\r\n"
            )
            conn.sendall(response.encode())
            return

        # Send upgrade response
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        conn.sendall(response.encode())

        if malicious:
            handle_malicious(conn, path)
        elif path == "/echo-origin":
            # Extract Origin header from upgrade request
            origin = ""
            for line in data.decode("utf-8", errors="replace").split("\r\n"):
                if line.lower().startswith("origin:"):
                    origin = line.split(":", 1)[1].strip()
                    break
            handle_echo_origin(conn, origin)
        else:
            handle_echo(conn)
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def handle_echo(conn):
    """Normal echo: reflect text/binary messages."""
    while True:
        frame_data = recv_frame(conn)
        if frame_data is None:
            break
        opcode, payload = frame_data

        if opcode == 0x8:  # Close
            send_frame(conn, 0x8, payload)
            break
        elif opcode == 0x9:  # Ping
            send_frame(conn, 0xA, payload)  # Pong
        elif opcode == 0x1 or opcode == 0x2:  # Text or Binary
            send_frame(conn, opcode, payload)  # Echo


def handle_echo_origin(conn, origin):
    """Echo the Origin header value back as first message, then echo normally."""
    # Wait for client to send a message first
    frame_data = recv_frame(conn)
    if frame_data is None:
        return
    # Send the origin value back as text
    send_frame(conn, 0x1, origin.encode("utf-8"))
    # Then continue as echo
    handle_echo(conn)


def handle_malicious(conn, path):
    """Send deliberately non-compliant frames based on path."""
    # Wait for the client to send a message first (trigger for sending bad frame)
    frame_data = recv_frame(conn)
    if frame_data is None:
        return

    if path == "/masked-frame":
        # H2: Server sends a MASKED frame (violates Section 5.1)
        send_masked_frame(conn, 0x1, b"masked from server")

    elif path == "/rsv-bits":
        # H1: Server sends frame with RSV1 bit set
        send_raw_frame(conn, fin=True, rsv1=True, opcode=0x1, payload=b"rsv1 set")

    elif path == "/oversized-ping":
        # C3: Server sends ping with >125 byte payload
        send_frame(conn, 0x9, b"A" * 200)

    elif path == "/fragmented-ping":
        # L1: Server sends ping with FIN=0
        send_raw_frame(conn, fin=False, rsv1=False, opcode=0x9, payload=b"ping")

    elif path == "/huge-payload":
        # C1: Server declares 1GB payload length but sends only a few bytes
        # This tests that the client rejects based on declared length,
        # not actual bytes received
        frame = bytearray()
        frame.append(0x81)  # FIN + text opcode
        frame.append(127)   # 8-byte extended length
        frame.extend(struct.pack("!Q", 1_000_000_000))  # 1 GB
        # Send just the header, then close — client should reject
        # before trying to allocate 1GB
        conn.sendall(bytes(frame))
        # Don't send any payload bytes; the client should reject on length alone

    elif path == "/invalid-close-code":
        # H3: Server sends close frame with invalid close code (999)
        payload = struct.pack("!H", 999) + b"invalid code"
        send_frame(conn, 0x8, payload)

    elif path == "/close-code-1005":
        # H3: Server sends close with reserved code 1005 (should not be on wire)
        payload = struct.pack("!H", 1005) + b"reserved"
        send_frame(conn, 0x8, payload)

    elif path == "/invalid-utf8":
        # H4: Server sends text frame with invalid UTF-8 bytes
        send_frame(conn, 0x1, b"\xff\xfe\x80\x81invalid utf8")

    elif path == "/bad-handshake-200":
        # M2: This path is handled specially in the handshake —
        # the malicious server will send a 200 OK instead of 101
        # (Already handled: the handshake code runs before this function)
        pass

    else:
        # Unknown path — just echo
        opcode, payload = frame_data
        send_frame(conn, opcode, payload)

    # Try to handle close gracefully
    try:
        frame_data = recv_frame(conn)
        if frame_data and frame_data[0] == 0x8:
            send_frame(conn, 0x8, frame_data[1])
    except (ConnectionError, OSError):
        pass


def recv_frame(conn):
    """Receive a WebSocket frame. Returns (opcode, payload) or None."""
    try:
        header = recv_exact(conn, 2)
        if not header:
            return None

        byte0, byte1 = header[0], header[1]
        opcode = byte0 & 0x0F
        masked = bool(byte1 & 0x80)
        payload_len = byte1 & 0x7F

        if payload_len == 126:
            ext = recv_exact(conn, 2)
            payload_len = struct.unpack("!H", ext)[0]
        elif payload_len == 127:
            ext = recv_exact(conn, 8)
            payload_len = struct.unpack("!Q", ext)[0]

        mask_key = recv_exact(conn, 4) if masked else b""
        payload = recv_exact(conn, payload_len) if payload_len > 0 else b""

        if masked and mask_key:
            payload = bytes(
                b ^ mask_key[i % 4] for i, b in enumerate(payload)
            )

        return (opcode, payload)
    except (ConnectionError, OSError):
        return None


def send_frame(conn, opcode, payload):
    """Send an unmasked WebSocket frame (server-to-client)."""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode

    payload_len = len(payload)
    if payload_len <= 125:
        frame.append(payload_len)
    elif payload_len <= 65535:
        frame.append(126)
        frame.extend(struct.pack("!H", payload_len))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", payload_len))

    frame.extend(payload)
    conn.sendall(bytes(frame))


def send_masked_frame(conn, opcode, payload):
    """Send a MASKED frame from server (deliberately non-compliant)."""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode

    mask_key = b"\x12\x34\x56\x78"
    payload_len = len(payload)

    if payload_len <= 125:
        frame.append(0x80 | payload_len)  # MASK bit set
    elif payload_len <= 65535:
        frame.append(0x80 | 126)
        frame.extend(struct.pack("!H", payload_len))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack("!Q", payload_len))

    frame.extend(mask_key)
    masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    frame.extend(masked_payload)
    conn.sendall(bytes(frame))


def send_raw_frame(conn, fin, rsv1, opcode, payload):
    """Send a frame with full control over header bits."""
    frame = bytearray()
    byte0 = opcode & 0x0F
    if fin:
        byte0 |= 0x80
    if rsv1:
        byte0 |= 0x40  # RSV1 bit
    frame.append(byte0)

    payload_len = len(payload)
    if payload_len <= 125:
        frame.append(payload_len)
    elif payload_len <= 65535:
        frame.append(126)
        frame.extend(struct.pack("!H", payload_len))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", payload_len))

    frame.extend(payload)
    conn.sendall(bytes(frame))


def recv_exact(conn, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def run_server(port, malicious=False):
    """Run a WebSocket server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(5)
    label = "malicious" if malicious else "echo"
    print(f"WebSocket {label} server running on ws://127.0.0.1:{port}")
    sys.stdout.flush()

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_client, args=(conn, addr, malicious)
            )
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    # Start echo server on 18081
    echo_thread = threading.Thread(target=run_server, args=(18081, False))
    echo_thread.daemon = True
    echo_thread.start()

    # Start malicious server on 18082
    run_server(18082, malicious=True)
