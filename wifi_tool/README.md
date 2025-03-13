# WiFi Penetration Testing Tool

A Python-based WiFi penetration testing tool with a modern graphical user interface. This tool provides various features for WiFi network security assessment, including network scanning, deauthentication attacks, and password cracking capabilities.

## Features

- Network scanning and information gathering
- Deauthentication attacks
- Password cracking (dictionary and brute-force methods)
- Modern, user-friendly GUI
- Real-time attack progress monitoring
- Detailed logging and reporting
- Configuration management

## Prerequisites

- Python 3.8 or higher
- Linux operating system (some features require specific wireless drivers)
- Wireless adapter supporting monitor mode
- Root/sudo privileges for certain operations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wifi-pentest-tool.git
cd wifi-pentest-tool
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
sudo python main.py
```

Root privileges are required for wireless interface operations.

### Network Scanning

1. Select the "Network Scanning" tab
2. Click "Scan for Networks" to start scanning
3. View discovered networks in the table
4. Select a network to view detailed information and signal strength visualization

### Deauthentication Attacks

1. Select the "Attacks" tab
2. Choose a target network from the scanning results
3. Select your wireless interface
4. Click "Start Deauth Attack" to begin
5. Monitor progress in real-time
6. Click "Stop Attack" to end the deauthentication

### Password Cracking

1. Select the "Attacks" tab
2. Choose between dictionary attack or brute-force methods
3. For dictionary attacks:
   - Select a dictionary file
   - Configure attack parameters
4. For brute-force attacks:
   - Set minimum and maximum password lengths
   - Configure character set options
5. Click "Start Password Cracking" to begin
6. Monitor progress and results in real-time

### Logging and Reports

1. Select the "Logs & Reports" tab
2. View real-time logs of all operations
3. Generate detailed PDF or text reports
4. Save and load attack configurations

## Configuration

The tool supports saving and loading configurations for:
- Network scan settings
- Attack parameters
- Interface preferences
- Logging options

Configuration files are stored in JSON format and can be managed through the GUI.

## Security Considerations

This tool is intended for authorized security testing only. Improper use may be illegal and is strictly prohibited. Always:

- Obtain proper authorization before testing
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use in controlled, authorized environments only

## Contributing

Contributions are welcome! Please feel free to submit pull requests. For major changes:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring all activities comply with local laws and regulations. The authors assume no liability for misuse or damage caused by this tool.

## Troubleshooting

### Common Issues

1. "No wireless interfaces found"
   - Ensure wireless adapter is properly connected
   - Verify adapter supports monitor mode
   - Check driver compatibility

2. "Permission denied"
   - Run the application with sudo/root privileges
   - Verify user permissions

3. "Monitor mode failed"
   - Ensure wireless adapter supports monitor mode
   - Check for conflicting processes
   - Verify driver compatibility

### Debug Mode

To run in debug mode with additional logging:
```bash
sudo python main.py --debug
```

## Support

For issues, questions, or contributions:
- Open an issue in the GitHub repository
- Check existing issues for solutions
- Include relevant logs and system information when reporting issues

## Acknowledgments

- PyQt5 for the GUI framework
- Scapy for packet manipulation
- The open-source security testing community
