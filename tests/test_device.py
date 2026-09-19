#!/usr/bin/env python3
"""
Unit tests for device discovery functionality.
Tests the real API: Device dataclass and DeviceDiscovery.
"""

import unittest
from unittest.mock import patch, MagicMock

from src.device import Device, DeviceDiscovery, ARPScanner

LINUX_ARP_SAMPLE = """Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   00:11:22:33:44:55   C                     eth0
192.168.1.2              ether   aa:bb:cc:dd:ee:ff   C                     eth0
"""

WINDOWS_ARP_SAMPLE = """Interface: 192.168.1.100 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.2           aa-bb-cc-dd-ee-ff     dynamic
"""

LINUX_ARP_INCOMPLETE = "? (192.168.1.99) at <incomplete> on eth0\n"


class TestDevice(unittest.TestCase):
    def test_device_creation(self):
        device = Device("192.168.1.1")
        self.assertEqual(device.ip, "192.168.1.1")
        self.assertIsNone(device.mac)
        self.assertIsNone(device.hostname)
        self.assertTrue(device.is_alive)

    def test_device_repr(self):
        # Device is a plain dataclass: no custom __str__, so repr is canonical.
        device = Device("192.168.1.1")
        self.assertEqual(
            repr(device),
            "Device(ip='192.168.1.1', mac=None, hostname=None, is_alive=True)"
        )

    def test_device_full(self):
        device = Device(ip="10.0.0.5", mac="00:11:22:33:44:55",
                        hostname="router.lan", is_alive=True)
        self.assertEqual(device.mac, "00:11:22:33:44:55")
        self.assertEqual(device.hostname, "router.lan")


class TestIsAlive(unittest.TestCase):
    def setUp(self):
        self.discovery = DeviceDiscovery(timeout=2)

    @patch("src.device.subprocess.run")
    def test_alive_on_zero_returncode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(self.discovery.is_alive("192.168.1.1"))

    @patch("src.device.subprocess.run")
    def test_dead_on_nonzero_returncode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(self.discovery.is_alive("192.168.1.1"))

    @patch("src.device.subprocess.run")
    def test_dead_on_exception(self, mock_run):
        mock_run.side_effect = FileNotFoundError("no ping")
        self.assertFalse(self.discovery.is_alive("192.168.1.1"))


class TestGetMacAddress(unittest.TestCase):
    def setUp(self):
        self.discovery = DeviceDiscovery(timeout=2)

    @patch("src.device.subprocess.run")
    def test_linux_arp_output(self, mock_run):
        self.discovery.system = "linux"
        mock_run.return_value = MagicMock(stdout=LINUX_ARP_SAMPLE)
        self.assertEqual(
            self.discovery.get_mac_address("192.168.1.1"),
            "00:11:22:33:44:55"
        )

    @patch("src.device.subprocess.run")
    def test_windows_arp_output(self, mock_run):
        self.discovery.system = "windows"
        mock_run.return_value = MagicMock(stdout=WINDOWS_ARP_SAMPLE)
        # Dashes normalized to colons
        self.assertEqual(
            self.discovery.get_mac_address("192.168.1.1"),
            "00:11:22:33:44:55"
        )

    @patch("src.device.subprocess.run")
    def test_uppercase_mac_normalized(self, mock_run):
        self.discovery.system = "linux"
        mock_run.return_value = MagicMock(
            stdout="192.168.1.1 ether AA:BB:CC:DD:EE:FF C eth0\n")
        self.assertEqual(
            self.discovery.get_mac_address("192.168.1.1"),
            "aa:bb:cc:dd:ee:ff"
        )

    @patch("src.device.subprocess.run")
    def test_no_mac_returns_none(self, mock_run):
        self.discovery.system = "linux"
        mock_run.return_value = MagicMock(stdout=LINUX_ARP_INCOMPLETE)
        self.assertIsNone(self.discovery.get_mac_address("192.168.1.99"))


class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.discovery = DeviceDiscovery(timeout=2)

    @patch.object(DeviceDiscovery, "is_alive")
    def test_discover_filters_dead_hosts(self, mock_alive):
        mock_alive.side_effect = lambda ip: ip in ("192.168.1.1", "192.168.1.3")
        devices = self.discovery.discover(
            ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"],
            resolve_hostname=False,
        )
        self.assertEqual(len(devices), 2)
        self.assertTrue(all(isinstance(d, Device) for d in devices))
        self.assertEqual({d.ip for d in devices}, {"192.168.1.1", "192.168.1.3"})

    @patch.object(DeviceDiscovery, "is_alive", return_value=False)
    def test_discover_none_alive(self, mock_alive):
        devices = self.discovery.discover(
            ["192.168.1.1", "192.168.1.2"], resolve_hostname=False)
        self.assertEqual(devices, [])

    def test_discover_subnet_invalid(self):
        self.assertEqual(
            self.discovery.discover_subnet("not-a-network",
                                           resolve_hostname=False), [])


class TestARPScanner(unittest.TestCase):
    def test_scan_network_without_scapy_returns_empty(self):
        # scapy is not installed in this environment; the scanner must
        # degrade gracefully to an empty result, not raise.
        scanner = ARPScanner()
        self.assertEqual(scanner.scan_network("192.168.1.0/30"), [])


if __name__ == "__main__":
    unittest.main()
