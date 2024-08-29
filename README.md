# sniffer-scanner
A very simple security tool for detecting suspicious network activity, unauthorized file changes, and potential rootkits. Monitors processes, network packets, and system logs to enhance system security.


## Wiretap Detection System

## Overview

This project is a wiretap detection system designed to monitor suspicious activities on a computer system. It performs various checks to detect potential wiretap activities, such as suspicious processes, unusual network activity, unauthorized file changes, and potential rootkits.

## Features

- **Process Monitoring**: Checks for known suspicious processes that may indicate the presence of wiretap tools.
- **Network Activity Monitoring**: Captures and logs outgoing network packets to detect suspicious activity.
- **File System Monitoring**: Monitors critical files for unauthorized changes.
- **System Logs Analysis**: Analyzes system logs for failed login attempts and other suspicious activities.
- **Rootkit Detection**: Checks for the presence of known rootkit files.

## Installation

### Prerequisites

- Python 3.x
- Required Python libraries:
  - `psutil`
  - `scapy`
  - `logging`

You can install the required libraries using pip:

```bash
pip install psutil scapy

Setup
Clone the repository:

bash
Kopiera kod
git clone [https://github.com/Z-eq/sniffer-scanner.git]
Navigate to the project directory:

bash
Kopiera kod
cd wiretap-detection
Create a virtual environment (optional but recommended):

bash
Kopiera kod
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
Install the required libraries:

bash
Kopiera kod
pip install psutil scapy
Usage
Run the script:

bash
Kopiera kod
python wiretap_detection.py
The script will continuously run and perform checks every 10 minutes. Logs will be saved to wiretap_detection.log.


