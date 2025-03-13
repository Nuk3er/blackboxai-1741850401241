from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QWidget, 
                           QVBoxLayout, QMessageBox)
from PyQt5.QtCore import Qt
from .scanning_tab import ScanningTab
from .attack_tab import AttackTab
from .logs_tab import LogsTab
from utils.logger import setup_logger

class MainWindow(QMainWindow):
    """Main window of the WiFi PenTest Tool."""
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger()
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        try:
            # Set window properties
            self.setWindowTitle('WiFi PenTest Tool')
            self.setMinimumSize(800, 600)

            # Create central widget and layout
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)

            # Create tab widget
            tabs = QTabWidget()
            
            # Initialize tabs
            self.scanning_tab = ScanningTab()
            self.attack_tab = AttackTab()
            self.logs_tab = LogsTab()

            # Add tabs to widget
            tabs.addTab(self.scanning_tab, "Network Scanning")
            tabs.addTab(self.attack_tab, "Attacks")
            tabs.addTab(self.logs_tab, "Logs & Reports")

            # Add tabs to layout
            layout.addWidget(tabs)

            # Connect signals between tabs
            self.scanning_tab.network_selected.connect(
                self.attack_tab.on_network_selected)

            self.logger.info("Main window initialized successfully")

        except Exception as e:
            self.logger.error(f"Error initializing main window: {str(e)}")
            QMessageBox.critical(self, "Error", 
                               f"Failed to initialize application: {str(e)}")

    def closeEvent(self, event):
        """Handle application closure."""
        try:
            # Cleanup and save any necessary state
            self.logger.info("Application closing...")
            event.accept()
        except Exception as e:
            self.logger.error(f"Error during application closure: {str(e)}")
            event.accept()
