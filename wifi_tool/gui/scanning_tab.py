from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, 
                           QTableWidget, QTableWidgetItem, QLabel,
                           QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from attacks.scanner import WiFiScanner
from utils.logger import setup_logger

class ScanWorker(QThread):
    """Worker thread for network scanning."""
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def run(self):
        """Execute the network scan."""
        try:
            scanner = WiFiScanner()
            networks = scanner.scan()
            self.finished.emit(networks)
        except Exception as e:
            self.error.emit(str(e))

class ScanningTab(QWidget):
    """Tab for WiFi network scanning and visualization."""
    
    network_selected = pyqtSignal(dict)  # Signal to share selected network info

    def __init__(self):
        super().__init__()
        self.logger = setup_logger()
        self.scanner_thread = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        try:
            layout = QVBoxLayout()

            # Scan button
            self.scan_button = QPushButton("Scan for Networks")
            self.scan_button.clicked.connect(self.start_scan)
            layout.addWidget(self.scan_button)

            # Progress bar
            self.progress_bar = QProgressBar()
            self.progress_bar.hide()
            layout.addWidget(self.progress_bar)

            # Network table
            self.network_table = QTableWidget()
            self.network_table.setColumnCount(4)
            self.network_table.setHorizontalHeaderLabels(
                ["SSID", "BSSID", "Channel", "Signal Strength"])
            self.network_table.itemSelectionChanged.connect(
                self.on_network_selection)
            layout.addWidget(self.network_table)

            # Matplotlib canvas for signal strength visualization
            self.figure = Figure()
            self.canvas = FigureCanvasQTAgg(self.figure)
            layout.addWidget(self.canvas)

            self.setLayout(layout)
            self.logger.info("Scanning tab initialized successfully")

        except Exception as e:
            self.logger.error(f"Error initializing scanning tab: {str(e)}")
            QMessageBox.critical(self, "Error", 
                               f"Failed to initialize scanning tab: {str(e)}")

    def start_scan(self):
        """Start the network scanning process."""
        try:
            self.scan_button.setEnabled(False)
            self.progress_bar.setRange(0, 0)
            self.progress_bar.show()

            self.scanner_thread = ScanWorker()
            self.scanner_thread.finished.connect(self.on_scan_complete)
            self.scanner_thread.error.connect(self.on_scan_error)
            self.scanner_thread.start()

        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}")
            self.scan_button.setEnabled(True)
            self.progress_bar.hide()
            QMessageBox.critical(self, "Error", 
                               f"Failed to start scanning: {str(e)}")

    def on_scan_complete(self, networks):
        """Handle completion of network scan."""
        try:
            self.network_table.setRowCount(len(networks))
            
            # Populate table with network information
            for row, network in enumerate(networks):
                self.network_table.setItem(row, 0, 
                    QTableWidgetItem(network['ssid']))
                self.network_table.setItem(row, 1, 
                    QTableWidgetItem(network['bssid']))
                self.network_table.setItem(row, 2, 
                    QTableWidgetItem(str(network['channel'])))
                self.network_table.setItem(row, 3, 
                    QTableWidgetItem(str(network['signal_strength'])))

            # Update signal strength visualization
            self.update_visualization(networks)
            
            self.scan_button.setEnabled(True)
            self.progress_bar.hide()
            self.logger.info(f"Scan completed. Found {len(networks)} networks.")

        except Exception as e:
            self.logger.error(f"Error processing scan results: {str(e)}")
            QMessageBox.critical(self, "Error", 
                               f"Failed to process scan results: {str(e)}")

    def on_scan_error(self, error_message):
        """Handle scanning errors."""
        self.logger.error(f"Scan error: {error_message}")
        self.scan_button.setEnabled(True)
        self.progress_bar.hide()
        QMessageBox.critical(self, "Scanning Error", str(error_message))

    def update_visualization(self, networks):
        """Update the signal strength visualization."""
        try:
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            
            ssids = [net['ssid'] for net in networks]
            signals = [net['signal_strength'] for net in networks]
            
            ax.bar(ssids, signals)
            ax.set_xlabel('Networks')
            ax.set_ylabel('Signal Strength (dBm)')
            ax.set_title('Network Signal Strengths')
            plt.xticks(rotation=45)
            
            self.figure.tight_layout()
            self.canvas.draw()

        except Exception as e:
            self.logger.error(f"Error updating visualization: {str(e)}")

    def on_network_selection(self):
        """Handle network selection in the table."""
        try:
            selected_items = self.network_table.selectedItems()
            if selected_items:
                row = selected_items[0].row()
                network_info = {
                    'ssid': self.network_table.item(row, 0).text(),
                    'bssid': self.network_table.item(row, 1).text(),
                    'channel': self.network_table.item(row, 2).text(),
                    'signal_strength': self.network_table.item(row, 3).text()
                }
                self.network_selected.emit(network_info)
                self.logger.info(f"Network selected: {network_info['ssid']}")

        except Exception as e:
            self.logger.error(f"Error handling network selection: {str(e)}")
