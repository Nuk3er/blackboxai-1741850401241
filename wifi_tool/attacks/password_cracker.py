import hashlib
import hmac
import threading
import time
import itertools
import string
from utils.logger import setup_logger

class PasswordCracker:
    """Class for performing WiFi password cracking attacks."""

    def __init__(self):
        self.logger = setup_logger()
        self.running = False
        self.thread = None
        self.progress_callback = None
        self.status_callback = None

    def set_callbacks(self, progress_callback=None, status_callback=None):
        """
        Set callback functions for progress updates.
        
        Args:
            progress_callback: Function to call with progress percentage
            status_callback: Function to call with status messages
        """
        self.progress_callback = progress_callback
        self.status_callback = status_callback

    def start_dictionary_attack(self, target_bssid, dict_file, ssid=None):
        """
        Start a dictionary-based password cracking attack.
        
        Args:
            target_bssid (str): BSSID of the target network
            dict_file (str): Path to dictionary file
            ssid (str): SSID of the target network (optional)
        """
        try:
            self.running = True
            self.thread = threading.Thread(
                target=self._dictionary_thread,
                args=(target_bssid, dict_file, ssid)
            )
            self.thread.daemon = True
            self.thread.start()

            self.logger.info(
                f"Started dictionary attack on {target_bssid} "
                f"using dictionary: {dict_file}"
            )

        except Exception as e:
            self.logger.error(f"Failed to start dictionary attack: {str(e)}")
            raise

    def start_bruteforce_attack(self, target_bssid, min_length=8, max_length=8,
                              charset=None, ssid=None):
        """
        Start a brute-force password cracking attack.
        
        Args:
            target_bssid (str): BSSID of the target network
            min_length (int): Minimum password length
            max_length (int): Maximum password length
            charset (str): Character set to use (default: ascii_letters + digits)
            ssid (str): SSID of the target network (optional)
        """
        try:
            if not charset:
                charset = string.ascii_letters + string.digits

            self.running = True
            self.thread = threading.Thread(
                target=self._bruteforce_thread,
                args=(target_bssid, min_length, max_length, charset, ssid)
            )
            self.thread.daemon = True
            self.thread.start()

            self.logger.info(
                f"Started brute-force attack on {target_bssid} "
                f"(length {min_length}-{max_length})"
            )

        except Exception as e:
            self.logger.error(f"Failed to start brute-force attack: {str(e)}")
            raise

    def stop_attack(self):
        """Stop the running password cracking attack."""
        try:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)
            self.logger.info("Password cracking attack stopped")

        except Exception as e:
            self.logger.error(f"Error stopping password cracking: {str(e)}")
            raise

    def _dictionary_thread(self, target_bssid, dict_file, ssid):
        """Thread function for dictionary-based attack."""
        try:
            total_lines = sum(1 for _ in open(dict_file, 'r', encoding='utf-8', 
                                            errors='ignore'))
            tested = 0
            
            with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                for password in f:
                    if not self.running:
                        break

                    password = password.strip()
                    tested += 1

                    # Update progress
                    if self.progress_callback:
                        progress = (tested / total_lines) * 100
                        self.progress_callback(int(progress))

                    if self.status_callback:
                        self.status_callback(f"Testing password: {password}")

                    # Test the password
                    if self._test_password(target_bssid, password, ssid):
                        self.logger.info(
                            f"Password found for {target_bssid}: {password}")
                        if self.status_callback:
                            self.status_callback(
                                f"Success! Password found: {password}")
                        return

            if self.running:
                self.logger.info("Dictionary attack completed - no match found")
                if self.status_callback:
                    self.status_callback("Attack completed - no match found")

        except Exception as e:
            self.logger.error(f"Dictionary attack thread error: {str(e)}")
            if self.status_callback:
                self.status_callback(f"Error: {str(e)}")
            self.running = False

    def _bruteforce_thread(self, target_bssid, min_length, max_length, 
                          charset, ssid):
        """Thread function for brute-force attack."""
        try:
            # Calculate total combinations for progress tracking
            total_combinations = sum(
                len(charset) ** i for i in range(min_length, max_length + 1))
            tested = 0

            # Try all possible combinations
            for length in range(min_length, max_length + 1):
                if not self.running:
                    break

                for guess in itertools.product(charset, repeat=length):
                    if not self.running:
                        break

                    password = ''.join(guess)
                    tested += 1

                    # Update progress periodically
                    if tested % 1000 == 0:
                        if self.progress_callback:
                            progress = (tested / total_combinations) * 100
                            self.progress_callback(int(progress))
                        
                        if self.status_callback:
                            self.status_callback(f"Testing password: {password}")

                    # Test the password
                    if self._test_password(target_bssid, password, ssid):
                        self.logger.info(
                            f"Password found for {target_bssid}: {password}")
                        if self.status_callback:
                            self.status_callback(
                                f"Success! Password found: {password}")
                        return

            if self.running:
                self.logger.info("Brute-force attack completed - no match found")
                if self.status_callback:
                    self.status_callback("Attack completed - no match found")

        except Exception as e:
            self.logger.error(f"Brute-force attack thread error: {str(e)}")
            if self.status_callback:
                self.status_callback(f"Error: {str(e)}")
            self.running = False

    def _test_password(self, target_bssid, password, ssid=None):
        """
        Test a password against the target network.
        
        Args:
            target_bssid (str): BSSID of the target network
            password (str): Password to test
            ssid (str): SSID of the target network (optional)
            
        Returns:
            bool: True if password is correct, False otherwise
        """
        try:
            # This is a simplified implementation
            # In a real-world scenario, you would:
            # 1. Generate the PMK (Pairwise Master Key) using PBKDF2
            # 2. Derive the PTK (Pairwise Transient Key)
            # 3. Verify the MIC (Message Integrity Code)
            
            # Simulate password testing with a delay
            time.sleep(0.01)
            
            # For demonstration purposes, we'll use a simple hash comparison
            # DO NOT use this in a real implementation
            if ssid:
                test_hash = hashlib.pbkdf2_hmac(
                    'sha1',
                    password.encode(),
                    ssid.encode(),
                    4096,
                    32
                )
                # In a real implementation, you would compare this against
                # the actual network hash
                return False
            
            return False

        except Exception as e:
            self.logger.error(f"Error testing password: {str(e)}")
            return False

    def _calculate_pmk(self, password, ssid):
        """
        Calculate the PMK (Pairwise Master Key).
        
        Args:
            password (str): Password to test
            ssid (str): Network SSID
            
        Returns:
            bytes: The calculated PMK
        """
        try:
            # WPA/WPA2 uses PBKDF2-HMAC-SHA1 with 4096 iterations
            # and a key length of 32 bytes
            pmk = hashlib.pbkdf2_hmac(
                'sha1',
                password.encode(),
                ssid.encode(),
                4096,
                32
            )
            return pmk

        except Exception as e:
            self.logger.error(f"Error calculating PMK: {str(e)}")
            raise

    def _calculate_ptk(self, pmk, anonce, snonce, ap_mac, client_mac):
        """
        Calculate the PTK (Pairwise Transient Key).
        
        Args:
            pmk (bytes): Pairwise Master Key
            anonce (bytes): AP nonce
            snonce (bytes): Client nonce
            ap_mac (bytes): AP MAC address
            client_mac (bytes): Client MAC address
            
        Returns:
            bytes: The calculated PTK
        """
        try:
            # PTK = PRF-X(PMK, "Pairwise key expansion" | Min(AP-MAC, Client-MAC) |
            #            Max(AP-MAC, Client-MAC) | Min(ANonce, SNonce) | 
            #            Max(ANonce, SNonce))
            
            data = b"Pairwise key expansion"
            min_mac = min(ap_mac, client_mac)
            max_mac = max(ap_mac, client_mac)
            min_nonce = min(anonce, snonce)
            max_nonce = max(anonce, snonce)
            
            data += min_mac + max_mac + min_nonce + max_nonce
            
            ptk = hmac.new(pmk, data, hashlib.sha1).digest()
            return ptk

        except Exception as e:
            self.logger.error(f"Error calculating PTK: {str(e)}")
            raise
