from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QTextEdit, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSlot
from utils.config import save_config, load_config
from utils.reporter import generate_report
from utils.logger import setup_logger
import json

class LogsTab(QWidget):
    """Tab for displaying logs and managing configurations."""

    def __init__(self):
        super().__init__()
        self.logger = setup_logger()
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        try:
            layout = QVBoxLayout()

            # Buttons layout
            buttons_layout = QHBoxLayout()

            # Configuration management buttons
            self.save_config_btn = QPushButton("Save Configuration")
            self.save_config_btn.clicked.connect(self.save_configuration)
            buttons_layout.addWidget(self.save_config_btn)

            self.load_config_btn = QPushButton("Load Configuration")
            self.load_config_btn.clicked.connect(self.load_configuration)
            buttons_layout.addWidget(self.load_config_btn)

            # Report generation button
            self.generate_report_btn = QPushButton("Generate Report")
            self.generate_report_btn.clicked.connect(self.generate_report)
            buttons_layout.addWidget(self.generate_report_btn)

            # Clear logs button
            self.clear_logs_btn = QPushButton("Clear Logs")
            self.clear_logs_btn.clicked.connect(self.clear_logs)
            buttons_layout.addWidget(self.clear_logs_btn)

            layout.addLayout(buttons_layout)

            # Log display area
            self.log_display = QTextEdit()
            self.log_display.setReadOnly(True)
            layout.addWidget(self.log_display)

            self.setLayout(layout)
            self.logger.info("Logs tab initialized successfully")

        except Exception as e:
            self.logger.error(f"Error initializing logs tab: {str(e)}")
            QMessageBox.critical(self, "Error", 
                               f"Failed to initialize logs tab: {str(e)}")

    def save_configuration(self):
        """Save current configuration to a file."""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Configuration",
                "", "JSON Files (*.json);;All Files (*)")
            
            if filename:
                config = self.get_current_config()
                save_config(config, filename)
                self.logger.info(f"Configuration saved to {filename}")
                self.log_display.append(f"Configuration saved to {filename}")

        except Exception as e:
            error_msg = f"Error saving configuration: {str(e)}"
            self.logger.error(error_msg)
            self.log_display.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def load_configuration(self):
        """Load configuration from a file."""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self, "Load Configuration",
                "", "JSON Files (*.json);;All Files (*)")
            
            if filename:
                config = load_config(filename)
                self.apply_config(config)
                self.logger.info(f"Configuration loaded from {filename}")
                self.log_display.append(f"Configuration loaded from {filename}")

        except Exception as e:
            error_msg = f"Error loading configuration: {str(e)}"
            self.logger.error(error_msg)
            self.log_display.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def generate_report(self):
        """Generate a report of the penetration testing session."""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Report",
                "", "PDF Files (*.pdf);;Text Files (*.txt);;All Files (*)")
            
            if filename:
                # Collect data for the report
                report_data = {
                    'logs': self.get_logs(),
                    'config': self.get_current_config(),
                    'results': self.get_test_results()
                }
                
                generate_report(report_data, filename)
                self.logger.info(f"Report generated: {filename}")
                self.log_display.append(f"Report generated: {filename}")

        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            self.logger.error(error_msg)
            self.log_display.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def clear_logs(self):
        """Clear the log display."""
        self.log_display.clear()
        self.logger.info("Logs cleared")

    def get_current_config(self):
        """Get current configuration settings."""
        # This would need to be implemented to collect current settings
        # from all tabs and components
        return {
            'version': '1.0',
            'timestamp': '',  # Add current timestamp
            'settings': {
                # Add actual settings here
            }
        }

    def apply_config(self, config):
        """Apply loaded configuration settings."""
        # This would need to be implemented to apply settings
        # to all tabs and components
        try:
            # Verify config structure
            if 'version' not in config or 'settings' not in config:
                raise ValueError("Invalid configuration format")

            # Apply settings
            settings = config['settings']
            # Apply to various components
            self.logger.info("Configuration applied successfully")

        except Exception as e:
            raise Exception(f"Failed to apply configuration: {str(e)}")

    def get_logs(self):
        """Get current logs."""
        return self.log_display.toPlainText()

    def get_test_results(self):
        """Get results from the penetration testing session."""
        # This would need to be implemented to collect results
        # from various components
        return {
            'timestamp': '',  # Add current timestamp
            'networks_found': [],
            'attacks_performed': [],
            'successful_attacks': []
        }

    @pyqtSlot(str)
    def append_log(self, message):
        """Append a message to the log display."""
        self.log_display.append(message)
