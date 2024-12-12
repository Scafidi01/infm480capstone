import tkinter as tk
from tkinter import ttk
import nmap
import paramiko
from scapy.all import sniff

# Initialize the main window
root = tk.Tk()
root.title("Home Network Vulnerability Scanner")
root.geometry("500x500")  # Window size

# Text widget to display output
output_text = tk.Text(root, height=15, width=60)
output_text.pack(pady=10)

# Function to update output in the text box
def display_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

# Clear the output
def clear_output():
    output_text.delete('1.0', tk.END)

# Function to scan open ports
def scan_ports():
    ip = ip_entry.get()  # Get IP from entry
    if not ip:
        display_output("Please enter a valid IP address.")
        return

    # Initialize Nmap scanner
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, '1-1024')  # Scan first 1024 ports
        for host in scanner.all_hosts():
            display_output(f"Host: {host} ({scanner[host].hostname()})")
            display_output(f"State: {scanner[host].state()}")
            for protocol in scanner[host].all_protocols():
                display_output(f"Protocol: {protocol}")
                ports = scanner[host][protocol].keys()
                for port in ports:
                    display_output(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")
    except Exception as e:
        display_output(f"Error: {str(e)}")

# Function to test SSH credentials
def test_ssh_credentials():
    ip = ip_entry.get()  # Get IP from entry
    username = ssh_user_entry.get()
    password = ssh_pass_entry.get()
    if not ip or not username or not password:
        display_output("Please enter IP, username, and password.")
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password)
        display_output(f"Success: Logged into {ip} with {username}:{password}")
        client.close()
    except paramiko.AuthenticationException:
        display_output(f"Failed to log in to {ip} with {username}:{password}")
    except Exception as e:
        display_output(f"Error: {str(e)}")

# Function to analyze network traffic
def analyze_traffic():
    interface = interface_entry.get()
    if not interface:
        display_output("Please enter a valid network interface (e.g., eth0, wlan0).")
        return

    # Sniff packets
    try:
        display_output("Sniffing 10 packets...")
        packets = sniff(iface=interface, count=10)
        for packet in packets:
            display_output(packet.summary())
    except Exception as e:
        display_output(f"Error: {str(e)}")

# Input fields
# IP address entry
tk.Label(root, text="Target IP Address:").pack(pady=5)
ip_entry = tk.Entry(root)
ip_entry.pack(pady=5)

# SSH Username entry
tk.Label(root, text="SSH Username:").pack(pady=5)
ssh_user_entry = tk.Entry(root)
ssh_user_entry.pack(pady=5)

# SSH Password entry
tk.Label(root, text="SSH Password:").pack(pady=5)
ssh_pass_entry = tk.Entry(root, show="*")  # Mask password input
ssh_pass_entry.pack(pady=5)

# Network Interface entry
tk.Label(root, text="Network Interface (e.g., eth0, wlan0):").pack(pady=5)
interface_entry = tk.Entry(root)
interface_entry.pack(pady=5)

# Buttons for each function
tk.Button(root, text="Scan Ports", command=scan_ports).pack(pady=5)
tk.Button(root, text="Test SSH Credentials", command=test_ssh_credentials).pack(pady=5)
tk.Button(root, text="Analyze Traffic", command=analyze_traffic).pack(pady=5)
tk.Button(root, text="Clear Output", command=clear_output).pack(pady=5)

# Run the main loop
root.mainloop()
