import socket
import nmap
from scapy.all import *

# Function to scan open ports
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024')  # Scan well-known ports
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for protocol in scanner[host].all_protocols():
            print(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in ports:
                print(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")

# Function to check for weak SSH passwords
def test_ssh_credentials(ip, username, password):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password)
        print(f"Success: Logged into {ip} with {username}:{password}")
        client.close()
    except paramiko.AuthenticationException:
        print(f"Failed to log in to {ip} with {username}:{password}")

# Function to analyze network traffic
def analyze_traffic(interface):
    sniff(iface=interface, prn=lambda x: x.summary(), count=10)

# Example usage
scan_ports("192.168.1.1")   # Replace with actual IP address
test_ssh_credentials("192.168.1.1", "admin", "password123")  # Example for SSH check
analyze_traffic("eth0")   # Replace with the correct network interface name
