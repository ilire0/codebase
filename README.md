# ITSec Wifi Testbed

## Description

The ITSec Wifi Testbed is a project designed to analyze and test WiFi security. It includes tools for scanning, detecting vulnerabilities, and analyzing network traffic. The project is structured to facilitate modular development and testing of WiFi security mechanisms.

## Project Structure

```
.gitignore
main.py
output/
  logs/
  reports/
    scan_results.json
README.md
scanner/
  __init__.py
  channel_hopper.py
  init.py
  packet_handler.py
  parsing_beaconframes.py
  scanner_state.py
scrapper.py
scrapper_v2.py
security/
  __init__.py
  attack_detection.py
  init.py
  vulnerability_scanner.py
utils/
  __init__.py
  helpers.py
  init.py
  logger.py
  report.py
```

-> scrapper + scrapper_v2 are depricated. (they work but they are bascially betaversion code.)

## Required Hardware/Depencies

- A Network Card / Wifi Adapter with Monitor Mode available (2.4Hz + 5Hz)
- Aircrack-ng (for easier setup)
- Python 3
- Scapy

Startup Monitor Mode + Code:

```bash
sudo modprobe -r brcmfmac
sudo modprobe brcmfmac
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo python3 main.py wlan0mon
```

Stop Monitor Mode + Code:

```bash
# CTRL+C
sudo airmon-ng stop wlan0mon
sudo modprobe -r brcmfmac
sudo modprobe brcmfmac
sudo systemctl restart NetworkManager
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://gitlab.hs-esslingen.de/ilemit00/itsec-wifi-testbed.git
   ```
2. Navigate to the project directory:
   ```bash
   cd itsec-wifi-testbed
   ```
3. Install the required dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

## Usage

- To run the main application:
  ```bash
  python main.py
  ```
- For specific modules, navigate to their respective directories and execute the scripts as needed.

## Features

- **WiFi Scanner**: Scans and logs WiFi networks.
- **Vulnerability Detection**: Identifies potential security issues in WiFi networks.
- **Logging and Reporting**: Generates detailed logs and reports for analysis.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

## Authors

This project is maintained by the ITSec team at Hochschule Esslingen.

## License

This project is licensed under the XXX License. See the LICENSE file for details.

## Acknowledgments

Special thanks to all contributors and the Hochschule Esslingen for their support.
