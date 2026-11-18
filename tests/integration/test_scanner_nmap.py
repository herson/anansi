"""Runs the real nmap binary: unit tests mock it, which is how C11 went unnoticed."""
import os
import shutil
import socket
import threading
import unittest

from modules.enumerator import ServiceEnumerator
from modules.scanner import NetworkScanner

# Ports in nmap's default top-1000 list, so the scanner's default port set covers them.
CANDIDATE_PORTS = (8888, 9999, 10000, 8443, 5555, 9090, 6667, 7777)


def _listen_on_a_free_candidate_port():
    for port in CANDIDATE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            sock.close()
            continue
        sock.listen()
        return sock, port
    return None, None


def _accept_and_close(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        conn.close()


@unittest.skipUnless(os.getenv("ANANSI_INTEGRATION") == "1", "set ANANSI_INTEGRATION=1 to run")
@unittest.skipUnless(shutil.which("nmap"), "nmap is not installed")
class TestScannerAgainstRealNmap(unittest.TestCase):

    def setUp(self):
        self.sock, self.port = _listen_on_a_free_candidate_port()
        if self.sock is None:
            self.skipTest(f"none of {CANDIDATE_PORTS} is free on 127.0.0.1")
        threading.Thread(target=_accept_and_close, args=(self.sock,), daemon=True).start()

    def tearDown(self):
        if self.sock is not None:
            self.sock.close()

    def test_finds_an_open_port_when_port_80_is_excluded(self):
        scan = NetworkScanner("127.0.0.1", 1, exclude_ports=[22, 80]).scan()
        found = {(f.host, f.port) for f in ServiceEnumerator(scan).enumerate()}
        self.assertIn(("127.0.0.1", self.port), found, scan.get("nmap", {}).get("command_line"))


if __name__ == "__main__":
    unittest.main()
