# test_std_compat.mojo — websocket must not break programs that use Mojo's std
#
# A Mojo program may declare each C function with one signature only. std
# declares errno access (__error / __errno_location), open/read/write, getenv
# and clock_gettime itself. websocket 1.1.3 declared __error /
# __errno_location with other types, so any program combining WebSocket with
# open(), listdir() or get_errno() failed to compile ("existing function with
# conflicting signature").
#
# Compiling this file is the test: it reaches WebSocket's network paths
# together with those std APIs. Running it exercises the std calls only.

from std.ffi import get_errno
from std.os import getenv, listdir
from std.sys import argv
from std.time import monotonic, perf_counter_ns
from websocket import WebSocket

comptime PATH = "/tmp/mojo_ws_std_compat.txt"


def network_paths() raises:
    """Never run: compiled so that WebSocket's C declarations are present."""
    var ws = WebSocket()
    ws.connect("wss://example.com/socket")
    ws.send_text("hi")
    _ = ws.recv()
    ws.close()


def main() raises:
    print("test_std_compat")
    if len(argv()) > 1000:
        network_paths()
    with open(PATH, "w") as f:
        f.write("std open() next to websocket\n")
    with open(PATH, "r") as f:
        if not f.read().startswith("std open()"):
            raise Error("std open()/read() round trip failed")
    _ = listdir("/tmp")
    _ = getenv("HOME")
    _ = get_errno()
    _ = perf_counter_ns() + monotonic()
    print("  PASS: WebSocket compiles next to std open/listdir/getenv/get_errno/clocks")
    print("Results: 1 passed, 0 failed")
