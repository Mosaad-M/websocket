# ============================================================================
# main.mojo — WebSocket Demo
# ============================================================================
#
# Connects to a public WebSocket echo service, sends a message, and prints
# the response.
#
# Usage: pixi run run
# ============================================================================

from websocket import WebSocket


def main() raises:
    print("=== WebSocket Demo ===")
    print()

    # Connect to a local echo server (start test_ws_server.py first)
    print("Connecting to ws://127.0.0.1:18081 ...")
    var ws = WebSocket()
    ws.connect("ws://127.0.0.1:18081")
    print("Connected!")
    print()

    # Send a text message
    var msg = "Hello from Mojo WebSocket!"
    print("Sending:", msg)
    ws.send_text(msg)

    # Receive the echo
    var frame = ws.recv()
    print("Received:", frame.as_text())
    print()

    # Send another message
    var msg2 = "Mojo + WebSockets = awesome"
    print("Sending:", msg2)
    ws.send_text(msg2)
    var frame2 = ws.recv()
    print("Received:", frame2.as_text())
    print()

    # Clean close
    print("Closing connection...")
    ws.close()
    print("Done!")
