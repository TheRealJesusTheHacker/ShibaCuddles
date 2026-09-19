#!/usr/bin/env python3
"""
Unit tests for port scanning functionality.
Tests the real API: PortScanner (src/port_scanner.py).
"""

import socket
import unittest
from unittest.mock import patch, MagicMock

from src.port_scanner import PortScanner, UDPScanner


class TestCheckPort(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner(threads=2, timeout=1)

    @patch("socket.socket")
    def test_port_open(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        self.assertTrue(self.scanner._check_port("192.168.1.1", 80))
        mock_socket.connect_ex.assert_called_once_with(("192.168.1.1", 80))
        mock_socket.close.assert_called()

    @patch("socket.socket")
    def test_port_closed(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1
        mock_socket_class.return_value = mock_socket

        self.assertFalse(self.scanner._check_port("192.168.1.1", 81))
        mock_socket.close.assert_called()

    @patch("socket.socket")
    def test_port_socket_error(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = socket.error("boom")
        mock_socket_class.return_value = mock_socket

        self.assertFalse(self.scanner._check_port("192.168.1.1", 80))
        # Socket must still be closed on the exception path
        mock_socket.close.assert_called()

    @patch("socket.socket")
    def test_port_connect_ex_raises_unexpected(self, mock_socket_class):
        # connect_ex raising (rather than returning non-zero) must not leak
        # the socket and must report the port as closed, not crash.
        mock_socket = MagicMock()
        mock_socket.connect_ex.side_effect = OSError("unreachable")
        mock_socket_class.return_value = mock_socket

        self.assertFalse(self.scanner._check_port("192.168.1.1", 80))
        mock_socket.close.assert_called()


class TestScan(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner(threads=4, timeout=1)

    @patch.object(PortScanner, "_check_port")
    def test_scan_ports_mixed(self, mock_check):
        mock_check.side_effect = [True, False, True, False, True]
        result = self.scanner.scan("192.168.1.1", "22,80,443,3306,8080")
        self.assertEqual(result, [22, 443, 8080])

    @patch.object(PortScanner, "_check_port", return_value=False)
    def test_scan_ports_none_open(self, mock_check):
        self.assertEqual(self.scanner.scan("192.168.1.1", "22,80"), [])

    @patch.object(PortScanner, "_check_port", return_value=True)
    def test_scan_ports_all_open_sorted(self, mock_check):
        result = self.scanner.scan("192.168.1.1", "8080,22,80")
        self.assertEqual(result, [22, 80, 8080])

    def test_scan_invalid_port_spec_returns_empty(self):
        # Invalid specs are logged and yield no ports, not an exception.
        self.assertEqual(self.scanner.scan("192.168.1.1", "1024-1"), [])


class TestGrabBanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner(threads=2, timeout=1)

    @patch("socket.socket")
    def test_banner_returned(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_class.return_value = mock_socket

        self.assertEqual(
            self.scanner.grab_banner("192.168.1.1", 22),
            "SSH-2.0-OpenSSH_8.9"
        )
        mock_socket.close.assert_called()

    @patch("socket.socket")
    def test_banner_failure_closes_socket(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("refused")
        mock_socket_class.return_value = mock_socket

        self.assertEqual(self.scanner.grab_banner("192.168.1.1", 22), "")
        mock_socket.close.assert_called()


class TestUDPScanner(unittest.TestCase):
    @patch("socket.socket")
    def test_udp_response_means_open(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.recvfrom.return_value = (b"data", ("192.168.1.1", 53))
        mock_socket_class.return_value = mock_socket

        scanner = UDPScanner(timeout=1)
        self.assertEqual(scanner.scan("192.168.1.1", [53]), [53])
        mock_socket.close.assert_called()

    @patch("socket.socket")
    def test_udp_timeout_not_open(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.recvfrom.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_socket

        scanner = UDPScanner(timeout=1)
        self.assertEqual(scanner.scan("192.168.1.1", [53]), [])
        mock_socket.close.assert_called()


if __name__ == "__main__":
    unittest.main()
