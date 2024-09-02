import os
import psutil
import logging
import scapy.all as scapy
from time import sleep
import platform

# Configure local logging
log_file = "wiretap_detection.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wiretap_detection')

# Detect the operating system
def get_os():
    return platform.system()

# Define lists of suspicious process names
suspicious_processes_linux = ["tcpdump", "wireshark", "ngrep"]
suspicious_processes_windows = ["tcpdump.exe", "Wireshark.exe", "ngrep.exe"]

# Function to check for suspicious processes
def check_processes():
    os_type = get_os()
    suspicious_processes = suspicious_processes_linux if os_type == 'Linux' else suspicious_processes_windows

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_info = proc.info
            if process_info['name'] in suspicious_processes:
                logger.warning(f"Suspicious process detected: {process_info}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Function to monitor network activity
def check_network_activity():
    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            ip_layer = packet.getlayer(scapy.IP)
            if ip_layer.dport == 80 or ip_layer.dport == 443:
                logger.info(f"Outgoing packet: {ip_layer.src} -> {ip_layer.dst}")

    scapy.sniff(prn=process_packet, count=10)

# Function to check for unauthorized file changes
def check_file_system():
    os_type = get_os()
    if os_type == 'Linux':
        monitored_files = ["/etc/passwd", "/etc/shadow"]
    else:
        monitored_files = ["C:\\Windows\\System32\\drivers\\etc\\hosts"]

    for file_path in monitored_files:
        if os.path.exists(file_path):
            st = os.stat(file_path)
            logger.info(f"File: {file_path} - Last modified: {st.st_mtime}")

# Function to analyze system logs
def check_system_logs():
    os_type = get_os()
    if os_type == 'Linux':
        log_file_path = "/var/log/auth.log"
        keyword = "FAILED LOGIN"
        with open(log_file_path, "r") as log_file:
            logs = log_file.readlines()
            for line in logs[-100:]:
                if keyword in line or "sudo" in line:
                    logger.warning(f"Suspicious log entry: {line.strip()}")
    else:
        # Windows Event Log reading not implemented
        logger.warning("Windows log reading not implemented.")

# Function to check for rootkits (simple check)
def check_rootkits():
    os_type = get_os()
    if os_type == 'Linux':
        rootkit_files = ["/usr/bin/ssh", "/usr/bin/netcat"]
    else:
        rootkit_files = ["C:\\Windows\\System32\\netcat.exe", "C:\\Windows\\System32\\ssh.exe"]

    for file in rootkit_files:
        if os.path.exists(file):
            logger.warning(f"Potential rootkit file found: {file}")

# Main function to run all checks.
def run_checks():
    logger.info("Starting wiretap detection checks...")
    check_processes()
    check_network_activity()
    check_file_system()
    check_system_logs()
    check_rootkits()
    logger.info("Wiretap detection checks completed.")

while True:
    run_checks()
    sleep(1800)  # Run checks every 30 minutes
