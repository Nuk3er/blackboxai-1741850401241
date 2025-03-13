import subprocess
import re
import platform
from utils.logger import setup_logger

class WiFiScanner:
    """Class for scanning and analyzing WiFi networks."""

    def __init__(self):
        self.logger = setup_logger()
        self.system = platform.system().lower()

    def scan(self):
        """
        Scan for available WiFi networks.
        Returns a list of dictionaries containing network information.
        """
        try:
            if self.system == "linux":
                return self._scan_linux()
            elif self.system == "darwin":  # macOS
                return self._scan_macos()
            elif self.system == "windows":
                return self._scan_windows()
            else:
                raise OSError(f"Unsupported operating system: {self.system}")

        except Exception as e:
            self.logger.error(f"Scanning error: {str(e)}")
            raise

    def _scan_linux(self):
        """Scan for networks on Linux using iwlist."""
        try:
            # Get wireless interfaces
            interfaces = self._get_wireless_interfaces_linux()
            if not interfaces:
                raise Exception("No wireless interfaces found")

            networks = []
            for interface in interfaces:
                try:
                    # Run iwlist scan
                    cmd = ["sudo", "iwlist", interface, "scan"]
                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                    output = output.decode('utf-8')

                    # Parse the output
                    cells = output.split('Cell ')
                    for cell in cells[1:]:  # Skip the first empty element
                        network = self._parse_linux_network(cell)
                        if network:
                            networks.append(network)

                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Error scanning interface {interface}: {str(e)}")
                    continue

            return networks

        except Exception as e:
            self.logger.error(f"Linux scanning error: {str(e)}")
            raise

    def _scan_macos(self):
        """Scan for networks on macOS using airport."""
        try:
            # Run airport scan
            cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                  "Versions/Current/Resources/airport", "-s"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            output = output.decode('utf-8')

            networks = []
            lines = output.split('\n')[1:]  # Skip header line
            for line in lines:
                if line.strip():
                    network = self._parse_macos_network(line)
                    if network:
                        networks.append(network)

            return networks

        except Exception as e:
            self.logger.error(f"macOS scanning error: {str(e)}")
            raise

    def _scan_windows(self):
        """Scan for networks on Windows using netsh."""
        try:
            # Run netsh scan
            cmd = ["netsh", "wlan", "show", "networks", "mode=Bssid"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            output = output.decode('utf-8', errors='ignore')

            networks = []
            current_network = {}
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('SSID'):
                    if current_network:
                        networks.append(current_network)
                    current_network = self._parse_windows_network(line)
                elif current_network and line:
                    self._update_windows_network(current_network, line)

            if current_network:
                networks.append(current_network)

            return networks

        except Exception as e:
            self.logger.error(f"Windows scanning error: {str(e)}")
            raise

    def _get_wireless_interfaces_linux(self):
        """Get list of wireless interfaces on Linux."""
        try:
            interfaces = []
            cmd = ["iwconfig"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            output = output.decode('utf-8')

            for line in output.split('\n'):
                if "IEEE 802.11" in line:  # This indicates a wireless interface
                    interface = line.split()[0]
                    interfaces.append(interface)

            return interfaces

        except Exception as e:
            self.logger.error(f"Error getting wireless interfaces: {str(e)}")
            return []

    def _parse_linux_network(self, cell_text):
        """Parse network information from Linux iwlist output."""
        try:
            network = {}
            
            # Extract SSID
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell_text)
            if ssid_match:
                network['ssid'] = ssid_match.group(1)
            else:
                return None

            # Extract BSSID
            bssid_match = re.search(r'Address: ([0-9A-F:]{17})', cell_text)
            if bssid_match:
                network['bssid'] = bssid_match.group(1)

            # Extract Channel
            channel_match = re.search(r'Channel:(\d+)', cell_text)
            if channel_match:
                network['channel'] = int(channel_match.group(1))

            # Extract Signal Level
            signal_match = re.search(r'Signal level=(-\d+) dBm', cell_text)
            if signal_match:
                network['signal_strength'] = int(signal_match.group(1))

            # Extract Encryption
            if 'Encryption key:on' in cell_text:
                network['encrypted'] = True
                if 'WPA2' in cell_text:
                    network['encryption_type'] = 'WPA2'
                elif 'WPA' in cell_text:
                    network['encryption_type'] = 'WPA'
                elif 'WEP' in cell_text:
                    network['encryption_type'] = 'WEP'
            else:
                network['encrypted'] = False
                network['encryption_type'] = 'None'

            return network

        except Exception as e:
            self.logger.error(f"Error parsing Linux network: {str(e)}")
            return None

    def _parse_macos_network(self, line):
        """Parse network information from macOS airport output."""
        try:
            parts = line.split()
            if len(parts) >= 5:
                return {
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'signal_strength': int(parts[2]),
                    'channel': int(parts[3]),
                    'encryption_type': parts[4],
                    'encrypted': parts[4] != 'NONE'
                }
            return None

        except Exception as e:
            self.logger.error(f"Error parsing macOS network: {str(e)}")
            return None

    def _parse_windows_network(self, ssid_line):
        """Parse initial network information from Windows netsh output."""
        try:
            ssid = ssid_line.split(':')[1].strip()
            return {
                'ssid': ssid,
                'bssid': None,
                'signal_strength': None,
                'channel': None,
                'encryption_type': None,
                'encrypted': False
            }

        except Exception as e:
            self.logger.error(f"Error parsing Windows network: {str(e)}")
            return None

    def _update_windows_network(self, network, line):
        """Update Windows network information with additional details."""
        try:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()

                if 'bssid' in key:
                    network['bssid'] = value
                elif 'signal' in key:
                    # Convert percentage to dBm (approximate)
                    percentage = int(value.replace('%', ''))
                    network['signal_strength'] = -100 + (percentage/2)
                elif 'channel' in key:
                    network['channel'] = int(value)
                elif 'authentication' in key:
                    network['encryption_type'] = value
                    network['encrypted'] = value != 'Open'

        except Exception as e:
            self.logger.error(f"Error updating Windows network: {str(e)}")
