from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QLabel, QProgressBar, QMessageBox, QGroupBox,
                           QLineEdit, QFileDialog, QSpinBox, QComboBox)
from PyQt5.QtCore import Qt, pyqtSlot, QThread, pyqtSignal
from attacks.deauth import DeauthAttack
from attacks.password_cracker import PasswordCracker
from utils.logger import setup_logger

class AttackWorker(QThread):
    """Worker thread for running attacks."""
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, attack_type, params):
        super().__init__()
        self.attack_type = attack_type
        self.params = params
        self.running = True

    def run(self):
        """Execute the selected attack."""
        try:
            if self.attack_type == "deauth":
                attack = DeauthAttack()
                attack.start_attack(
                    target_bssid=self.params['bssid'],
                    interface=self.params['interface']
                )
            elif self.attack_type == "password":
                cracker = PasswordCracker()
                if self.params['method'] == 'dictionary':
                    cracker.start_dictionary_attack(
                        target_bssid=self.params['bssid'],
                        dict_file=self.params['dict_file']
                    )
                else:  # brute-force
                    cracker.start_bruteforce_attack(
                        target_bssid=self.params['bssid'],
                        min_length=self.params['min_length'],
                        max_length=self.params['max_length']
                    )
            self.finished.emit()
            
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        """Stop the running attack."""
        self.running = False

class AttackTab(QWidget):
    """Tab for launching various WiFi attacks."""

    def __init__(self):
        super().__init__()
        self.logger = setup_logger()
        self.selected_network = None
        self.attack_thread = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        try:
            layout = QVBoxLayout()

            # Network info display
            self.network_info = QLabel("No network selected")
            layout.addWidget(self.network_info)

            # Deauthentication Attack Section
            deauth_group = QGroupBox("Deauthentication Attack")
            deauth_layout = QVBoxLayout()

            # Interface selection
            interface_layout = QHBoxLayout()
            interface_layout.addWidget(QLabel("Interface:"))
            self.interface_combo = QComboBox()
            self.interface_combo.addItems(self.get_wireless_interfaces())
            interface_layout.addWidget(self.interface_combo)
            deauth_layout.addLayout(interface_layout)

            # Deauth control buttons
            deauth_buttons = QHBoxLayout()
            self.start_deauth_btn = QPushButton("Start Deauth Attack")
            self.start_deauth_btn.clicked.connect(
                lambda: self.start_attack("deauth"))
            self.stop_deauth_btn = QPushButton("Stop Attack")
            self.stop_deauth_btn.clicked.connect(self.stop_attack)
            self.stop_deauth_btn.setEnabled(False)
            deauth_buttons.addWidget(self.start_deauth_btn)
            deauth_buttons.addWidget(self.stop_deauth_btn)
            deauth_layout.addLayout(deauth_buttons)

            deauth_group.setLayout(deauth_layout)
            layout.addWidget(deauth_group)

            # Password Cracking Section
            password_group = QGroupBox("Password Cracking")
            password_layout = QVBoxLayout()

            # Attack method selection
            method_layout = QHBoxLayout()
            method_layout.addWidget(QLabel("Method:"))
            self.method_combo = QComboBox()
            self.method_combo.addItems(["Dictionary Attack", "Brute Force"])
            self.method_combo.currentTextChanged.connect(
                self.on_method_changed)
            method_layout.addWidget(self.method_combo)
            password_layout.addLayout(method_layout)

            # Dictionary attack options
            self.dict_widget = QWidget()
            dict_layout = QHBoxLayout()
            self.dict_path = QLineEdit()
            self.dict_path.setPlaceholder("Select dictionary file...")
            self.dict_browse = QPushButton("Browse")
            self.dict_browse.clicked.connect(self.browse_dictionary)
            dict_layout.addWidget(self.dict_path)
            dict_layout.addWidget(self.dict_browse)
            self.dict_widget.setLayout(dict_layout)
            password_layout.addWidget(self.dict_widget)

            # Brute force options
            self.brute_widget = QWidget()
            brute_layout = QHBoxLayout()
            brute_layout.addWidget(QLabel("Min Length:"))
            self.min_length = QSpinBox()
            self.min_length.setRange(1, 32)
            brute_layout.addWidget(self.min_length)
            brute_layout.addWidget(QLabel("Max Length:"))
            self.max_length = QSpinBox()
            self.max_length.setRange(1, 32)
            self.max_length.setValue(8)
            brute_layout.addWidget(self.max_length)
            self.brute_widget.setLayout(brute_layout)
            self.brute_widget.hide()
            password_layout.addWidget(self.brute_widget)

            # Password cracking control buttons
            crack_buttons = QHBoxLayout()
            self.start_crack_btn = QPushButton("Start Password Cracking")
            self.start_crack_btn.clicked.connect(
                lambda: self.start_attack("password"))
            self.stop_crack_btn = QPushButton("Stop Attack")
            self.stop_crack_btn.clicked.connect(self.stop_attack)
            self.stop_crack_btn.setEnabled(False)
            crack_buttons.addWidget(self.start_crack_btn)
            crack_buttons.addWidget(self.stop_crack_btn)
            password_layout.addLayout(crack_buttons)

            password_group.setLayout(password_layout)
            layout.addWidget(password_group)

            # Progress bar
            self.progress_bar = QProgressBar()
            self.progress_bar.hide()
            layout.addWidget(self.progress_bar)

            # Status label
            self.status_label = QLabel()
            layout.addWidget(self.status_label)

            self.setLayout(layout)
            self.logger.info("Attack tab initialized successfully")

        except Exception as e:
            self.logger.error(f"Error initializing attack tab: {str(e)}")
            QMessageBox.critical(self, "Error", 
                               f"Failed to initialize attack tab: {str(e)}")

    def get_wireless_interfaces(self):
        """Get list of wireless interfaces."""
        # This would need to be implemented based on the system
        # For now, return a dummy list
        return ["wlan0", "wlan1"]

    @pyqtSlot(dict)
    def on_network_selected(self, network_info):
        """Handle network selection from scanning tab."""
        self.selected_network = network_info
        self.network_info.setText(
            f"Selected Network: {network_info['ssid']} ({network_info['bssid']})")
        self.logger.info(f"Attack tab updated with network: {network_info['ssid']}")

    def on_method_changed(self, method):
        """Handle change in password cracking method."""
        if method == "Dictionary Attack":
            self.dict_widget.show()
            self.brute_widget.hide()
        else:
            self.dict_widget.hide()
            self.brute_widget.show()

    def browse_dictionary(self):
        """Open file dialog to select dictionary file."""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Dictionary File", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.dict_path.setText(filename)

    def start_attack(self, attack_type):
        """Start the selected attack."""
        if not self.selected_network:
            QMessageBox.warning(self, "Warning", "No network selected!")
            return

        try:
            params = {
                'bssid': self.selected_network['bssid'],
                'interface': self.interface_combo.currentText()
            }

            if attack_type == "password":
                if self.method_combo.currentText() == "Dictionary Attack":
                    if not self.dict_path.text():
                        QMessageBox.warning(self, "Warning", 
                                          "Please select a dictionary file!")
                        return
                    params['method'] = 'dictionary'
                    params['dict_file'] = self.dict_path.text()
                else:
                    params['method'] = 'bruteforce'
                    params['min_length'] = self.min_length.value()
                    params['max_length'] = self.max_length.value()

            self.attack_thread = AttackWorker(attack_type, params)
            self.attack_thread.progress.connect(self.update_progress)
            self.attack_thread.status.connect(self.update_status)
            self.attack_thread.finished.connect(self.on_attack_finished)
            self.attack_thread.error.connect(self.on_attack_error)
            
            self.attack_thread.start()
            self.progress_bar.show()
            self.toggle_attack_controls(True)
            self.logger.info(f"Started {attack_type} attack on {self.selected_network['ssid']}")

        except Exception as e:
            self.logger.error(f"Error starting attack: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to start attack: {str(e)}")

    def stop_attack(self):
        """Stop the running attack."""
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.stop()
            self.attack_thread.wait()
            self.toggle_attack_controls(False)
            self.logger.info("Attack stopped by user")

    def toggle_attack_controls(self, attack_running):
        """Toggle controls based on attack state."""
        self.start_deauth_btn.setEnabled(not attack_running)
        self.stop_deauth_btn.setEnabled(attack_running)
        self.start_crack_btn.setEnabled(not attack_running)
        self.stop_crack_btn.setEnabled(attack_running)

    def update_progress(self, value):
        """Update progress bar."""
        self.progress_bar.setValue(value)

    def update_status(self, message):
        """Update status label."""
        self.status_label.setText(message)

    def on_attack_finished(self):
        """Handle attack completion."""
        self.toggle_attack_controls(False)
        self.progress_bar.hide()
        self.status_label.setText("Attack completed")
        self.logger.info("Attack completed successfully")

    def on_attack_error(self, error_message):
        """Handle attack errors."""
        self.toggle_attack_controls(False)
        self.progress_bar.hide()
        self.status_label.setText(f"Error: {error_message}")
        self.logger.error(f"Attack error: {error_message}")
        QMessageBox.critical(self, "Attack Error", str(error_message))
