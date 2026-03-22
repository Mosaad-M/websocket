# ============================================================================
# test_websocket.mojo — WebSocket Client Tests
# ============================================================================
#
# Requires test_ws_server.py running on localhost:18081
#
# ============================================================================

from websocket import WebSocket, WebSocketFrame, WS_OPCODE_TEXT, WS_OPCODE_BINARY, WS_OPCODE_CLOSE


alias TEST_URL = "ws://127.0.0.1:18081"
alias MALICIOUS_URL = "ws://127.0.0.1:18082"


# ============================================================================
# Test Helpers
# ============================================================================


def assert_str_eq(actual: String, expected: String, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected '" + expected + "', got '" + actual + "'"
        )


def assert_int_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(
            label + ": expected " + String(expected) + ", got " + String(actual)
        )


def assert_true(condition: Bool, label: String) raises:
    if not condition:
        raise Error(label + ": expected True")


# ============================================================================
# Tests
# ============================================================================


def test_connect_and_close() raises:
    """Connect to echo server and close cleanly."""
    var ws = WebSocket()
    ws.connect(TEST_URL)
    assert_true(ws._connected, "connected after handshake")
    ws.close()
    assert_true(not ws._connected, "disconnected after close")


def test_send_recv_text() raises:
    """Send text message and verify echo."""
    var ws = WebSocket()
    ws.connect(TEST_URL)
    ws.send_text("hello websocket")
    var frame = ws.recv()
    assert_int_eq(Int(frame.opcode), Int(WS_OPCODE_TEXT), "opcode")
    assert_str_eq(frame.as_text(), "hello websocket", "echoed text")
    ws.close()


def test_send_recv_binary() raises:
    """Send binary message and verify echo."""
    var ws = WebSocket()
    ws.connect(TEST_URL)
    var data = List[UInt8](capacity=4)
    data.append(0xDE)
    data.append(0xAD)
    data.append(0xBE)
    data.append(0xEF)
    ws.send_binary(data)
    var frame = ws.recv()
    assert_int_eq(Int(frame.opcode), Int(WS_OPCODE_BINARY), "opcode")
    assert_int_eq(len(frame.payload), 4, "payload length")
    assert_int_eq(Int(frame.payload[0]), 0xDE, "byte 0")
    assert_int_eq(Int(frame.payload[1]), 0xAD, "byte 1")
    assert_int_eq(Int(frame.payload[2]), 0xBE, "byte 2")
    assert_int_eq(Int(frame.payload[3]), 0xEF, "byte 3")
    ws.close()


def test_multiple_messages() raises:
    """Send and receive multiple messages on same connection."""
    var ws = WebSocket()
    ws.connect(TEST_URL)

    ws.send_text("first")
    var f1 = ws.recv()
    assert_str_eq(f1.as_text(), "first", "message 1")

    ws.send_text("second")
    var f2 = ws.recv()
    assert_str_eq(f2.as_text(), "second", "message 2")

    ws.send_text("third")
    var f3 = ws.recv()
    assert_str_eq(f3.as_text(), "third", "message 3")

    ws.close()


def test_medium_message() raises:
    """Send message >125 bytes (tests 2-byte extended length encoding)."""
    var ws = WebSocket()
    ws.connect(TEST_URL)

    # Build a 200-byte message
    var buf = List[UInt8](capacity=200)
    for i in range(200):
        buf.append(UInt8(65 + (i % 26)))  # A-Z repeating
    var msg = String(unsafe_from_utf8=buf^)
    ws.send_text(msg)
    var frame = ws.recv()
    assert_int_eq(len(frame.payload), 200, "medium payload length")
    assert_str_eq(frame.as_text(), msg, "medium message echo")
    ws.close()


def test_large_message() raises:
    """Send message >65535 bytes (tests 8-byte extended length encoding)."""
    var ws = WebSocket()
    ws.connect(TEST_URL)

    # Build a 70000-byte message
    var size = 70000
    var buf = List[UInt8](capacity=size)
    for i in range(size):
        buf.append(UInt8(48 + (i % 10)))  # 0-9 repeating
    var msg = String(unsafe_from_utf8=buf^)
    ws.send_text(msg)
    var frame = ws.recv()
    assert_int_eq(len(frame.payload), size, "large payload length")
    # Check first and last chars
    var text = frame.as_text()
    var text_bytes = text.as_bytes()
    assert_int_eq(Int(text_bytes[0]), 48, "first byte")
    assert_int_eq(Int(text_bytes[size - 1]), 48 + ((size - 1) % 10), "last byte")
    ws.close()


def test_empty_message() raises:
    """Send empty text message."""
    var ws = WebSocket()
    ws.connect(TEST_URL)
    ws.send_text("")
    var frame = ws.recv()
    assert_int_eq(Int(frame.opcode), Int(WS_OPCODE_TEXT), "opcode")
    assert_int_eq(len(frame.payload), 0, "empty payload length")
    ws.close()


def test_connect_failure() raises:
    """Connection to non-existent server should raise."""
    var ws = WebSocket()
    var raised = False
    try:
        ws.connect("ws://127.0.0.1:19999/nope")
    except:
        raised = True
    if not raised:
        raise Error("expected connection error")


# ============================================================================
# Security Tests (require malicious server on localhost:18082)
# ============================================================================


def test_security_masked_server_frame() raises:
    """H2: Server sends masked frame — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/masked-frame")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "masked"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for masked server frame")


def test_security_rsv_bits() raises:
    """H1: Server sends frame with RSV1 bit set — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/rsv-bits")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "RSV"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for non-zero RSV bits")


def test_security_oversized_ping() raises:
    """C3: Server sends ping with >125 byte payload — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/oversized-ping")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "control frame"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for oversized ping")


def test_security_fragmented_ping() raises:
    """L1: Server sends ping with FIN=0 — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/fragmented-ping")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "fragmented control"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for fragmented control frame")


def test_security_huge_payload() raises:
    """C1: Server declares 1GB payload — client rejects without allocating."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/huge-payload")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "too large"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for huge payload")


def test_security_custom_max_frame_size() raises:
    """Configurable max_frame_size is enforced."""
    var ws = WebSocket()
    ws.max_frame_size = 100  # 100 bytes max
    ws.connect(TEST_URL)
    # Send a 200-byte message — echo will exceed our 100-byte limit
    var buf = List[UInt8](capacity=200)
    for i in range(200):
        buf.append(UInt8(65 + (i % 26)))
    ws.send_text(String(unsafe_from_utf8=buf^))
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "too large"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for frame exceeding custom max_frame_size")


# ============================================================================
# Session 2 Security Tests
# ============================================================================


def test_security_invalid_close_code() raises:
    """H3: Server sends close frame with invalid code 999 — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/invalid-close-code")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "invalid close code"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for invalid close code")


def test_security_close_code_1005() raises:
    """H3: Server sends close with reserved code 1005 — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/close-code-1005")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "invalid close code"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for reserved close code 1005")


def test_security_invalid_utf8() raises:
    """H4: Server sends text frame with invalid UTF-8 — client MUST reject."""
    var ws = WebSocket()
    ws.connect(MALICIOUS_URL + "/invalid-utf8")
    ws.send_text("trigger")
    var raised = False
    try:
        _ = ws.recv()
    except e:
        if _err_contains(String(e), "invalid UTF-8"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for invalid UTF-8 text frame")


def test_security_bad_handshake_200() raises:
    """M2: Server responds with HTTP 200 instead of 101 — client MUST reject."""
    var ws = WebSocket()
    var raised = False
    try:
        ws.connect(MALICIOUS_URL + "/bad-handshake-200")
    except e:
        if _err_contains(String(e), "handshake failed"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for non-101 handshake response")


def test_security_bad_handshake_accept() raises:
    """M2: Server responds with wrong Sec-WebSocket-Accept — client MUST reject."""
    var ws = WebSocket()
    var raised = False
    try:
        ws.connect(MALICIOUS_URL + "/bad-handshake-accept")
    except e:
        if _err_contains(String(e), "handshake failed"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for invalid Sec-WebSocket-Accept")


# ============================================================================
# Session 3 Security Tests
# ============================================================================


def test_security_ssrf_private_ip() raises:
    """SSRF: Connection to private IP blocked when allow_private_ips=False."""
    var ws = WebSocket()
    ws.allow_private_ips = False
    var raised = False
    try:
        ws.connect("ws://127.0.0.1:18081")
    except e:
        if _err_contains(String(e), "private") or _err_contains(
            String(e), "SSRF"
        ):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected SSRF protection to block private IP")


def test_security_send_size_limit() raises:
    """M4: Send exceeding max_send_size is rejected."""
    var ws = WebSocket()
    ws.max_send_size = 100  # 100 bytes max
    ws.connect(TEST_URL)
    # Try to send 200 bytes — should be rejected before sending
    var buf = List[UInt8](capacity=200)
    for i in range(200):
        buf.append(UInt8(65 + (i % 26)))
    var raised = False
    try:
        ws.send_text(String(unsafe_from_utf8=buf^))
    except e:
        if _err_contains(String(e), "send payload too large"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for send exceeding max_send_size")


def test_security_send_binary_size_limit() raises:
    """M4: Binary send exceeding max_send_size is rejected."""
    var ws = WebSocket()
    ws.max_send_size = 50  # 50 bytes max
    ws.connect(TEST_URL)
    var data = List[UInt8](capacity=100)
    for i in range(100):
        data.append(UInt8(i % 256))
    var raised = False
    try:
        ws.send_binary(data)
    except e:
        if _err_contains(String(e), "send payload too large"):
            raised = True
        else:
            raise Error("unexpected error: " + String(e))
    if not raised:
        raise Error("expected error for binary send exceeding max_send_size")


def test_security_origin_header() raises:
    """Origin header appears in handshake when set."""
    var ws = WebSocket()
    ws.origin = "https://example.com"
    ws.connect(TEST_URL + "/echo-origin")
    ws.send_text("trigger")
    var frame = ws.recv()
    assert_str_eq(
        frame.as_text(), "https://example.com", "origin header echoed"
    )
    ws.close()


def _err_contains(haystack: String, needle: String) -> Bool:
    """Check if error message contains a substring."""
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    var h_len = len(h)
    var n_len = len(n)
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var found = True
        for j in range(n_len):
            if h[i + j] != n[j]:
                found = False
                break
        if found:
            return True
    return False


# ============================================================================
# Test Runner
# ============================================================================


def main() raises:
    var passed = 0
    var failed = 0

    def run_test(
        name: String,
        mut passed: Int,
        mut failed: Int,
        test_fn: def () raises -> None,
    ):
        try:
            test_fn()
            print("  PASS:", name)
            passed += 1
        except e:
            print("  FAIL:", name, "-", String(e))
            failed += 1

    print("=== WebSocket Tests ===")
    print("(Requires test_ws_server.py: echo on :18081, malicious on :18082)")
    print()

    # Functional tests
    run_test("connect and close", passed, failed, test_connect_and_close)
    run_test("send/recv text", passed, failed, test_send_recv_text)
    run_test("send/recv binary", passed, failed, test_send_recv_binary)
    run_test("multiple messages", passed, failed, test_multiple_messages)
    run_test(
        "medium message (>125 bytes)", passed, failed, test_medium_message
    )
    run_test(
        "large message (>65535 bytes)", passed, failed, test_large_message
    )
    run_test("empty message", passed, failed, test_empty_message)
    run_test("connect failure", passed, failed, test_connect_failure)

    # Security tests
    print()
    print("--- Security Tests ---")
    print()
    run_test(
        "[H2] masked server frame rejected",
        passed,
        failed,
        test_security_masked_server_frame,
    )
    run_test(
        "[H1] RSV bits rejected",
        passed,
        failed,
        test_security_rsv_bits,
    )
    run_test(
        "[C3] oversized ping rejected",
        passed,
        failed,
        test_security_oversized_ping,
    )
    run_test(
        "[L1] fragmented ping rejected",
        passed,
        failed,
        test_security_fragmented_ping,
    )
    run_test(
        "[C1] huge payload rejected",
        passed,
        failed,
        test_security_huge_payload,
    )
    run_test(
        "[C1] custom max_frame_size enforced",
        passed,
        failed,
        test_security_custom_max_frame_size,
    )

    print()
    print("--- Session 2 Security Tests ---")
    print()
    run_test(
        "[H3] invalid close code rejected",
        passed,
        failed,
        test_security_invalid_close_code,
    )
    run_test(
        "[H3] reserved close code 1005 rejected",
        passed,
        failed,
        test_security_close_code_1005,
    )
    run_test(
        "[H4] invalid UTF-8 text rejected",
        passed,
        failed,
        test_security_invalid_utf8,
    )
    run_test(
        "[M2] bad handshake 200 rejected",
        passed,
        failed,
        test_security_bad_handshake_200,
    )
    run_test(
        "[M2] bad handshake accept rejected",
        passed,
        failed,
        test_security_bad_handshake_accept,
    )

    print()
    print("--- Session 3 Security Tests ---")
    print()
    run_test(
        "SSRF private IP blocked",
        passed,
        failed,
        test_security_ssrf_private_ip,
    )
    run_test(
        "[M4] send text size limit enforced",
        passed,
        failed,
        test_security_send_size_limit,
    )
    run_test(
        "[M4] send binary size limit enforced",
        passed,
        failed,
        test_security_send_binary_size_limit,
    )
    run_test(
        "Origin header in handshake",
        passed,
        failed,
        test_security_origin_header,
    )

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
