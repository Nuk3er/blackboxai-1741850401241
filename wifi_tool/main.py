#!/usr/bin/env python3

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from gui.main_window import MainWindow
from utils.logger import setup_logger

def main():
    """Main entry point of the WiFi PenTest Tool."""
    try:
        # Initialize logging
        logger = setup_logger()
        logger.info("Starting WiFi PenTest Tool...")

        # Create Qt Application
        app = QApplication(sys.argv)
        
        # Load stylesheet
        try:
            with open('assets/styles.css', 'r') as style:
                app.setStyleSheet(style.read())
        except Exception as e:
            logger.warning(f"Could not load stylesheet: {str(e)}")

        # Create and show the main window
        window = MainWindow()
        window.show()

        # Start the event loop
        sys.exit(app.exec_())

    except Exception as e:
        logger.error(f"Application failed to start: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
