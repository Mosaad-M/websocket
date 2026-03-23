# ============================================================================
# websocket.mojo — WebSocket Client (RFC 6455)
# ============================================================================
#
# Native Mojo WebSocket client built on top of the tcp/tls modules.
# Supports ws:// and wss:// connections, text/binary messages, ping/pong,
# and clean close handshake.
#
# Uses pure-Mojo crypto (from tls_pure) for SHA-1, Base64, and random bytes
# needed by the WebSocket handshake and frame masking.
#
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc, UnsafePointer
from std.sys import CompilationTarget


def _get_errno() -> Int32:
    """Read errno without a C shim. Uses __errno_location (Linux) or __error (macOS).
    comptime if ensures only the live branch is compiled, avoiding unresolved symbols."""
    comptime if CompilationTarget.is_linux():
        var ptr = external_call["__errno_location", Int]()
        var ebuf = alloc[Int32](1)
        _ = external_call["memcpy", Int](Int(ebuf), ptr, Int(4))
        var val = ebuf[]
        ebuf.free()
        return val
    else:
        var ptr = external_call["__error", Int]()
        var ebuf = alloc[Int32](1)
        _ = external_call["memcpy", Int](Int(ebuf), ptr, Int(4))
        var val = ebuf[]
        ebuf.free()
        return val

from tcp import TcpSocket
from tls.socket import TlsSocket, load_system_ca_bundle
from url import parse_url

from crypto.sha1 import sha1
from crypto.base64 import base64_encode
from crypto.random import csprng_bytes


# ============================================================================
# WebSocket Constants
# ============================================================================

alias WS_OPCODE_CONTINUATION: UInt8 = 0x0
alias WS_OPCODE_TEXT: UInt8 = 0x1
alias WS_OPCODE_BINARY: UInt8 = 0x2
alias WS_OPCODE_CLOSE: UInt8 = 0x8
alias WS_OPCODE_PING: UInt8 = 0x9
alias WS_OPCODE_PONG: UInt8 = 0xA

alias WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Default limits
alias DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB
alias DEFAULT_MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16 MB
alias DEFAULT_MAX_SEND_SIZE = 16 * 1024 * 1024  # 16 MB

# Close codes
alias WS_CLOSE_NORMAL: Int = 1000
alias WS_CLOSE_PROTOCOL_ERROR: Int = 1002
alias WS_CLOSE_TOO_BIG: Int = 1009



# ============================================================================
# WebSocket Frame
# ============================================================================


struct WebSocketFrame(Copyable, Movable):
    """A decoded WebSocket frame."""

    var fin: Bool
    var opcode: UInt8
    var payload: List[UInt8]

    def __init__(out self):
        self.fin = True
        self.opcode = WS_OPCODE_TEXT
        self.payload = List[UInt8]()

    def __init__(out self, fin: Bool, opcode: UInt8, payload: List[UInt8]):
        self.fin = fin
        self.opcode = opcode
        self.payload = payload.copy()

    def __copyinit__(out self, copy: Self):
        self.fin = copy.fin
        self.opcode = copy.opcode
        self.payload = copy.payload.copy()

    def __moveinit__(out self, deinit take: Self):
        self.fin = take.fin
        self.opcode = take.opcode
        self.payload = take.payload^

    def as_text(self) -> String:
        """Interpret payload as UTF-8 text."""
        var copy = self.payload.copy()
        return String(unsafe_from_utf8=copy^)


# ============================================================================
# WebSocket Connection
# ============================================================================


struct WebSocket(Movable):
    """WebSocket client connection (RFC 6455).

    Supports ws:// (plain TCP) and wss:// (TLS) connections.

    Usage:
        var ws = WebSocket()
        ws.connect("ws://echo.example.com/ws")
        ws.send_text("hello")
        var frame = ws.recv()
        print(frame.as_text())
        ws.close()
    """

    var _tcp: TcpSocket
    var _tls: TlsSocket
    var _use_tls: Bool
    var _connected: Bool
    var _host: String
    var _path: String
    var max_message_size: Int
    var max_frame_size: Int
    var max_send_size: Int
    var allow_private_ips: Bool
    var origin: String

    def __init__(out self):
        self._tcp = TcpSocket()
        self._tls = TlsSocket(Int32(0))
        self._use_tls = False
        self._connected = False
        self._host = String("")
        self._path = String("")
        self.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        self.max_frame_size = DEFAULT_MAX_FRAME_SIZE
        self.max_send_size = DEFAULT_MAX_SEND_SIZE
        self.allow_private_ips = True
        self.origin = String("")

    def __moveinit__(out self, deinit take: Self):
        self._tcp = take._tcp^
        self._tls = take._tls^
        self._use_tls = take._use_tls
        self._connected = take._connected
        self._host = take._host^
        self._path = take._path^
        self.max_message_size = take.max_message_size
        self.max_frame_size = take.max_frame_size
        self.max_send_size = take.max_send_size
        self.allow_private_ips = take.allow_private_ips
        self.origin = take.origin^

    def connect(mut self, url_str: String) raises:
        """Connect to a WebSocket server.

        Parses the URL, establishes TCP/TLS connection, and performs
        the HTTP upgrade handshake.

        Args:
            url_str: WebSocket URL (ws:// or wss://)
        """
        var url = parse_url(url_str)

        if url.scheme != "ws" and url.scheme != "wss":
            raise Error(
                "unsupported WebSocket scheme: "
                + url.scheme
                + " (expected ws:// or wss://)"
            )

        self._use_tls = url.scheme == "wss"
        self._host = url.host
        self._path = url.request_path()

        # M1: Validate path for CRLF injection before using in HTTP request
        _validate_no_crlf(self._path, "request path")

        # Step 1: TCP connect (with optional SSRF protection)
        self._tcp.connect(
            url.host,
            url.port,
            reject_private_ips=not self.allow_private_ips,
        )

        # Step 2: TLS handshake if wss://
        if self._use_tls:
            var trust_anchors = load_system_ca_bundle()
            self._tls = TlsSocket(self._tcp.fd)
            self._tls.connect(url.host, trust_anchors)

        # Step 3: WebSocket upgrade handshake
        self._handshake(url.host_header())

        self._connected = True

    def send_text(mut self, data: String) raises:
        """Send a text message."""
        var bytes = data.as_bytes()
        # M4: Enforce send payload size limit
        if len(bytes) > self.max_send_size:
            raise Error(
                "WebSocket send payload too large: "
                + String(len(bytes))
                + " bytes (max "
                + String(self.max_send_size)
                + ")"
            )
        var payload = List[UInt8](capacity=len(bytes))
        for i in range(len(bytes)):
            payload.append(bytes[i])
        self._send_frame(WS_OPCODE_TEXT, payload)

    def send_binary(mut self, data: List[UInt8]) raises:
        """Send a binary message."""
        # M4: Enforce send payload size limit
        if len(data) > self.max_send_size:
            raise Error(
                "WebSocket send payload too large: "
                + String(len(data))
                + " bytes (max "
                + String(self.max_send_size)
                + ")"
            )
        self._send_frame(WS_OPCODE_BINARY, data)

    def send_ping(mut self, payload: String = "") raises:
        """Send a ping control frame."""
        var bytes = payload.as_bytes()
        var data = List[UInt8](capacity=len(bytes))
        for i in range(len(bytes)):
            data.append(bytes[i])
        self._send_frame(WS_OPCODE_PING, data)

    def recv(mut self) raises -> WebSocketFrame:
        """Receive the next complete message.

        Handles control frames internally:
        - Ping: auto-sends Pong, continues reading
        - Close: sends Close response, marks disconnected
        - Continuation: accumulates fragments until FIN=1
        """
        if not self._connected:
            raise Error("WebSocket not connected")

        # Accumulator for fragmented messages
        var accumulated = List[UInt8]()
        var message_opcode: UInt8 = 0

        while True:
            var frame = self._recv_frame()

            # Handle control frames (can appear between fragments)
            if frame.opcode == WS_OPCODE_PING:
                # Auto-respond with Pong
                self._send_frame(WS_OPCODE_PONG, frame.payload)
                continue

            if frame.opcode == WS_OPCODE_PONG:
                # Ignore unsolicited pongs
                continue

            if frame.opcode == WS_OPCODE_CLOSE:
                # H3: Validate close code if present
                if len(frame.payload) >= 2:
                    var close_code = (Int(frame.payload[0]) << 8) | Int(
                        frame.payload[1]
                    )
                    if not _is_valid_close_code(close_code):
                        raise Error(
                            "WebSocket protocol error: invalid close"
                            " code "
                            + String(close_code)
                        )
                elif len(frame.payload) == 1:
                    # Close payload must be 0 or >= 2 bytes (code is 2 bytes)
                    raise Error(
                        "WebSocket protocol error: close frame with 1"
                        " byte payload"
                    )
                # Send close response if we haven't already
                if self._connected:
                    # Echo back the close payload (status code + reason)
                    try:
                        self._send_frame(WS_OPCODE_CLOSE, frame.payload)
                    except:
                        pass  # Best effort
                    self._connected = False
                return frame^

            # Handle data frames (text, binary, continuation)
            if frame.opcode == WS_OPCODE_CONTINUATION:
                # Append to accumulated payload
                for i in range(len(frame.payload)):
                    accumulated.append(frame.payload[i])
                # C2: Check accumulated size limit
                if len(accumulated) > self.max_message_size:
                    raise Error(
                        "WebSocket message too large: accumulated "
                        + String(len(accumulated))
                        + " bytes (max "
                        + String(self.max_message_size)
                        + ")"
                    )
                if frame.fin:
                    # H4: Validate UTF-8 for text messages
                    if message_opcode == WS_OPCODE_TEXT:
                        if not _validate_utf8(accumulated):
                            raise Error(
                                "WebSocket protocol error: invalid"
                                " UTF-8 in text message"
                            )
                    return WebSocketFrame(True, message_opcode, accumulated)
            else:
                # New message (text or binary)
                if frame.fin:
                    # Single-frame message
                    # H4: Validate UTF-8 for text messages
                    if frame.opcode == WS_OPCODE_TEXT:
                        if not _validate_utf8(frame.payload):
                            raise Error(
                                "WebSocket protocol error: invalid"
                                " UTF-8 in text message"
                            )
                    return WebSocketFrame(
                        frame.fin, frame.opcode, frame.payload
                    )
                else:
                    # First fragment — start accumulating
                    message_opcode = frame.opcode
                    accumulated = frame.payload.copy()

        # Unreachable, but required by Mojo
        return WebSocketFrame()

    def close(mut self, code: Int = 1000, reason: String = "") raises:
        """Send close frame and shut down the connection.

        Args:
            code: WebSocket close status code (default 1000 = normal)
            reason: Human-readable close reason
        """
        if not self._connected:
            return

        # H3: Validate the close code we're sending
        if not _is_valid_close_code(code):
            raise Error(
                "WebSocket error: invalid close code " + String(code)
            )

        # Build close payload: 2-byte status code (big-endian) + reason
        var reason_bytes = reason.as_bytes()
        var payload = List[UInt8](capacity=2 + len(reason_bytes))
        payload.append(UInt8((code >> 8) & 0xFF))
        payload.append(UInt8(code & 0xFF))
        for i in range(len(reason_bytes)):
            payload.append(reason_bytes[i])

        self._send_frame(WS_OPCODE_CLOSE, payload)

        # Try to read the close response (best effort)
        try:
            var response = self._recv_frame()
            _ = response^
        except:
            pass

        self._connected = False

        # Close underlying connections
        if self._use_tls:
            try:
                self._tls.close()
            except:
                pass
        self._tcp.close()

    # ========================================================================
    # Private Methods
    # ========================================================================

    def _handshake(mut self, host_header: String) raises:
        """Perform the WebSocket HTTP upgrade handshake."""
        # Generate 16-byte random key, base64 encode it
        var key_bytes = csprng_bytes(16)
        var ws_key = base64_encode(key_bytes)

        # Build the upgrade request
        var buf = List[UInt8](capacity=512)
        _buf_append_str(buf, "GET ")
        _buf_append_str(buf, self._path)
        _buf_append_str(buf, " HTTP/1.1\r\n")
        _buf_append_str(buf, "Host: ")
        _buf_append_str(buf, host_header)
        _buf_append_str(buf, "\r\n")
        _buf_append_str(buf, "Upgrade: websocket\r\n")
        _buf_append_str(buf, "Connection: Upgrade\r\n")
        _buf_append_str(buf, "Sec-WebSocket-Key: ")
        _buf_append_str(buf, ws_key)
        _buf_append_str(buf, "\r\n")
        _buf_append_str(buf, "Sec-WebSocket-Version: 13\r\n")
        # Optional Origin header (helps servers with CSWSH protection)
        if len(self.origin) > 0:
            _buf_append_str(buf, "Origin: ")
            _buf_append_str(buf, self.origin)
            _buf_append_str(buf, "\r\n")
        _buf_append_str(buf, "\r\n")

        # Send the request
        var request = String(unsafe_from_utf8=buf^)
        self._raw_send_str(request)

        # Read response
        var response = self._read_handshake_response()

        # M2: Strict status line validation
        _validate_handshake_response(response, ws_key)

    def _read_handshake_response(mut self) raises -> String:
        """Read the HTTP handshake response until \\r\\n\\r\\n."""
        var buf = List[UInt8](capacity=4096)

        while True:
            var chunk = self._recv_exact(1)
            buf.append(chunk[0])

            # Check for \r\n\r\n at the end
            var blen = len(buf)
            if blen >= 4:
                if (
                    buf[blen - 4] == 13
                    and buf[blen - 3] == 10
                    and buf[blen - 2] == 13
                    and buf[blen - 1] == 10
                ):
                    break

            if blen > 16384:
                raise Error("handshake response too large")

        return String(unsafe_from_utf8=buf^)

    def _send_frame(
        mut self, opcode: UInt8, payload: List[UInt8]
    ) raises:
        """Build and send a masked WebSocket frame.

        Client-to-server frames MUST be masked per RFC 6455 Section 5.3.
        """
        if not self._connected and opcode != WS_OPCODE_CLOSE:
            raise Error("WebSocket not connected")

        var payload_len = len(payload)
        var mask_key = csprng_bytes(4)

        # Calculate frame size
        var header_size = 2 + 4  # base header + mask key
        if payload_len > 65535:
            header_size += 8  # 8-byte extended length
        elif payload_len > 125:
            header_size += 2  # 2-byte extended length

        var frame = List[UInt8](capacity=header_size + payload_len)

        # Byte 0: FIN=1 | opcode
        frame.append(0x80 | opcode)

        # Byte 1: MASK=1 | payload length
        if payload_len <= 125:
            frame.append(0x80 | UInt8(payload_len))
        elif payload_len <= 65535:
            frame.append(0x80 | UInt8(126))
            frame.append(UInt8((payload_len >> 8) & 0xFF))
            frame.append(UInt8(payload_len & 0xFF))
        else:
            frame.append(0x80 | UInt8(127))
            # 8-byte big-endian length
            for i in range(7, -1, -1):
                frame.append(UInt8((payload_len >> (i * 8)) & 0xFF))

        # Masking key (4 bytes)
        for i in range(4):
            frame.append(mask_key[i])

        # Masked payload
        for i in range(payload_len):
            frame.append(payload[i] ^ mask_key[i % 4])

        # Send the entire frame
        var frame_str = _bytes_to_string(frame)
        self._raw_send_str(frame_str)

    def _recv_frame(mut self) raises -> WebSocketFrame:
        """Receive and decode a single WebSocket frame.

        Validates per RFC 6455:
        - RSV bits must be 0 (no extensions negotiated)
        - Server frames must NOT be masked
        - Control frames must have payload <= 125 bytes
        - Control frames must not be fragmented (FIN must be 1)
        - Payload size must not exceed max_frame_size
        """
        # Read 2-byte header
        var header = self._recv_exact(2)
        var byte0 = header[0]
        var byte1 = header[1]

        var fin = Bool(byte0 & 0x80)
        var opcode = byte0 & 0x0F
        var masked = Bool(byte1 & 0x80)
        var payload_len = Int(byte1 & 0x7F)

        # H1: RSV bits must be 0 (Section 5.2)
        if byte0 & 0x70 != 0:
            raise Error(
                "WebSocket protocol error: non-zero RSV bits (no extensions"
                " negotiated)"
            )

        # H2: Server-to-client frames MUST NOT be masked (Section 5.1)
        if masked:
            raise Error(
                "WebSocket protocol error: server sent masked frame"
            )

        var is_control = opcode >= 0x8

        # L1: Control frames MUST NOT be fragmented (Section 5.5)
        if is_control and not fin:
            raise Error(
                "WebSocket protocol error: fragmented control frame"
            )

        # Extended payload length
        if payload_len == 126:
            var ext = self._recv_exact(2)
            payload_len = (Int(ext[0]) << 8) | Int(ext[1])
        elif payload_len == 127:
            var ext = self._recv_exact(8)
            payload_len = 0
            for i in range(8):
                payload_len = (payload_len << 8) | Int(ext[i])

        # C3: Control frames MUST have payload <= 125 bytes (Section 5.5)
        if is_control and payload_len > 125:
            raise Error(
                "WebSocket protocol error: control frame payload exceeds"
                " 125 bytes ("
                + String(payload_len)
                + ")"
            )

        # C1: Enforce max frame payload size to prevent memory exhaustion
        if payload_len > self.max_frame_size:
            raise Error(
                "WebSocket frame payload too large: "
                + String(payload_len)
                + " bytes (max "
                + String(self.max_frame_size)
                + ")"
            )

        # Read payload (safe — size is bounded)
        var payload = List[UInt8]()
        if payload_len > 0:
            payload = self._recv_exact(payload_len)

        return WebSocketFrame(fin, opcode, payload^)

    def _recv_exact(mut self, n: Int) raises -> List[UInt8]:
        """Read exactly n bytes from the socket."""
        var result = List[UInt8](capacity=n)

        while len(result) < n:
            var remaining = n - len(result)

            if self._use_tls:
                # Use TlsSocket.recv() which handles TLS record buffering
                var chunk = self._tls.recv(remaining)
                if len(chunk) == 0:
                    raise Error("TLS connection closed in _recv_exact")
                for i in range(len(chunk)):
                    result.append(chunk[i])
            else:
                var buf = alloc[UInt8](remaining)
                var ret = external_call["recv", Int](
                    self._tcp.fd, Int(buf), remaining, Int32(0)
                )
                if ret < 0:
                    # Check for EINTR (errno=4) — retry on signal interruption
                    if _get_errno() == 4:
                        buf.free()
                        continue
                    buf.free()
                    raise Error("TCP read failed in _recv_exact")
                elif ret == 0:
                    buf.free()
                    raise Error("TCP read failed in _recv_exact")
                for i in range(Int(ret)):
                    result.append((buf + i)[])
                buf.free()

        return result^

    def _raw_send_str(mut self, data: String) raises:
        """Send raw string data over TCP or TLS."""
        if self._use_tls:
            var raw = data.as_bytes()
            var bytes = List[UInt8](capacity=len(raw))
            for i in range(len(raw)):
                bytes.append(raw[i])
            _ = self._tls.send(bytes)
        else:
            _ = self._tcp.send(data)


# ============================================================================
# Helper Functions
# ============================================================================


def _compute_accept_key(ws_key: String) -> String:
    """Compute Sec-WebSocket-Accept from the client key.

    Accept = Base64(SHA-1(key + MAGIC))
    """
    var concat = ws_key + WS_MAGIC
    var concat_raw = concat.as_bytes()
    var concat_bytes = List[UInt8](capacity=len(concat_raw))
    for i in range(len(concat_raw)):
        concat_bytes.append(concat_raw[i])
    var hash = sha1(concat_bytes)
    return base64_encode(hash)


def _buf_append_str(mut buf: List[UInt8], s: String):
    """Append string bytes to a byte buffer."""
    var bytes = s.as_bytes()
    for i in range(len(bytes)):
        buf.append(bytes[i])


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a List[UInt8] to a String (raw bytes, not UTF-8 validated)."""
    var copy = data.copy()
    return String(unsafe_from_utf8=copy^)


def _str_contains(haystack: String, needle: String) -> Bool:
    """Check if haystack contains needle (case-sensitive)."""
    var h_bytes = haystack.as_bytes()
    var n_bytes = needle.as_bytes()
    var h_len = len(h_bytes)
    var n_len = len(n_bytes)
    if n_len == 0:
        return True
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if h_bytes[i + j] != n_bytes[j]:
                found = False
                break
        if found:
            return True
    return False


def _validate_no_crlf(s: String, label: String) raises:
    """M1: Reject strings containing CR or LF to prevent CRLF injection."""
    var b = s.as_bytes()
    for i in range(len(b)):
        if b[i] == 13 or b[i] == 10:
            raise Error(
                "WebSocket security error: CRLF injection in " + label
            )


def _validate_handshake_response(
    response: String, ws_key: String
) raises:
    """M2: Strictly validate the HTTP upgrade handshake response.

    Checks:
    - Status line is exactly HTTP/1.1 101
    - Sec-WebSocket-Accept header matches expected value (case-insensitive key)
    """
    var bytes = response.as_bytes()
    var blen = len(bytes)

    # Find end of first line (first \r\n)
    var first_line_end = -1
    for i in range(blen - 1):
        if bytes[i] == 13 and bytes[i + 1] == 10:
            first_line_end = i
            break

    if first_line_end < 0:
        raise Error("WebSocket handshake failed: no status line")

    # Extract status line and check for "HTTP/1.1 101"
    var status_buf = List[UInt8](capacity=first_line_end)
    for i in range(first_line_end):
        status_buf.append(bytes[i])
    var status_line = String(unsafe_from_utf8=status_buf^)

    # Must start with "HTTP/1.1 101"
    if not _str_starts_with(status_line, "HTTP/1.1 101"):
        raise Error(
            "WebSocket handshake failed: expected HTTP/1.1 101, got: "
            + status_line
        )

    # Parse headers — find Sec-WebSocket-Accept
    var expected_accept = _compute_accept_key(ws_key)
    var found_accept = False
    var i = first_line_end + 2  # skip first \r\n

    while i < blen - 1:
        # Find end of this header line
        var line_end = -1
        for j in range(i, blen - 1):
            if bytes[j] == 13 and bytes[j + 1] == 10:
                line_end = j
                break
        if line_end < 0 or line_end == i:
            break  # empty line = end of headers

        # Find colon separator
        var colon_pos = -1
        for j in range(i, line_end):
            if bytes[j] == 58:  # ':'
                colon_pos = j
                break

        if colon_pos > 0:
            # Extract header key (case-insensitive comparison)
            var key_buf = List[UInt8](capacity=colon_pos - i)
            for j in range(i, colon_pos):
                key_buf.append(bytes[j])
            var key = String(unsafe_from_utf8=key_buf^)

            if _eq_ignore_case(key, "Sec-WebSocket-Accept"):
                # Extract value (skip colon and whitespace)
                var val_start = colon_pos + 1
                while val_start < line_end and bytes[val_start] == 32:
                    val_start += 1
                var val_buf = List[UInt8](capacity=line_end - val_start)
                for j in range(val_start, line_end):
                    val_buf.append(bytes[j])
                var val = String(unsafe_from_utf8=val_buf^)

                if val != expected_accept:
                    raise Error(
                        "WebSocket handshake failed: invalid"
                        " Sec-WebSocket-Accept"
                    )
                found_accept = True

        i = line_end + 2  # skip \r\n

    if not found_accept:
        raise Error(
            "WebSocket handshake failed: missing Sec-WebSocket-Accept"
            " header"
        )


def _str_starts_with(s: String, prefix: String) -> Bool:
    """Check if string starts with prefix."""
    var s_bytes = s.as_bytes()
    var p_bytes = prefix.as_bytes()
    if len(p_bytes) > len(s_bytes):
        return False
    for i in range(len(p_bytes)):
        if s_bytes[i] != p_bytes[i]:
            return False
    return True


def _eq_ignore_case(a: String, b: String) -> Bool:
    """Case-insensitive string comparison."""
    var a_bytes = a.as_bytes()
    var b_bytes = b.as_bytes()
    if len(a_bytes) != len(b_bytes):
        return False
    for i in range(len(a_bytes)):
        var ca = a_bytes[i]
        var cb = b_bytes[i]
        # Convert uppercase to lowercase
        if ca >= 65 and ca <= 90:
            ca = ca + 32
        if cb >= 65 and cb <= 90:
            cb = cb + 32
        if ca != cb:
            return False
    return True


def _is_valid_close_code(code: Int) -> Bool:
    """H3: Validate WebSocket close status code per RFC 6455 Section 7.4.1.

    Valid codes: 1000-1003, 1007-1011, 3000-4999.
    Reserved codes NOT valid on the wire: 1005, 1006, 1015.
    """
    if code >= 1000 and code <= 1003:
        return True
    if code >= 1007 and code <= 1011:
        return True
    if code >= 3000 and code <= 4999:
        return True
    return False


def _validate_utf8(data: List[UInt8]) -> Bool:
    """H4: Validate that byte sequence is valid UTF-8.

    Checks:
    - Correct multi-byte sequence lengths (1-4 bytes)
    - Valid continuation bytes (10xxxxxx)
    - No overlong encodings
    - No surrogates (U+D800-U+DFFF)
    - No codepoints above U+10FFFF
    """
    var i = 0
    var n = len(data)

    while i < n:
        var b = data[i]

        if b <= 0x7F:
            # Single byte (ASCII)
            i += 1
        elif b >= 0xC2 and b <= 0xDF:
            # 2-byte sequence (0xC0, 0xC1 are overlong)
            if i + 1 >= n:
                return False
            if (data[i + 1] & 0xC0) != 0x80:
                return False
            i += 2
        elif b >= 0xE0 and b <= 0xEF:
            # 3-byte sequence
            if i + 2 >= n:
                return False
            var b1 = data[i + 1]
            var b2 = data[i + 2]
            if (b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80:
                return False
            # Check overlong (E0 requires b1 >= A0)
            if b == 0xE0 and b1 < 0xA0:
                return False
            # Check surrogates (ED requires b1 < A0)
            if b == 0xED and b1 >= 0xA0:
                return False
            i += 3
        elif b >= 0xF0 and b <= 0xF4:
            # 4-byte sequence
            if i + 3 >= n:
                return False
            var b1 = data[i + 1]
            var b2 = data[i + 2]
            var b3 = data[i + 3]
            if (
                (b1 & 0xC0) != 0x80
                or (b2 & 0xC0) != 0x80
                or (b3 & 0xC0) != 0x80
            ):
                return False
            # Check overlong (F0 requires b1 >= 90)
            if b == 0xF0 and b1 < 0x90:
                return False
            # Check above U+10FFFF (F4 requires b1 < 90)
            if b == 0xF4 and b1 >= 0x90:
                return False
            i += 4
        else:
            # Invalid start byte (0x80-0xBF, 0xC0-0xC1, 0xF5-0xFF)
            return False

    return True
