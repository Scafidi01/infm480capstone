import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sr1, IP, ICMP, ARP, Ether
import ipaddress
import threading
import nmap
import sqlite3
import datetime

# Initialize Nmap for port scanning
nm = nmap.PortScanner()


# Set up SQLite database
def setup_database():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY,
                        date TEXT,
                        ip TEXT,
                        hostname TEXT,
                        mac_address TEXT,
                        open_ports TEXT
                     )''')
    conn.commit()
    conn.close()


# Save scan results to the database
def save_scan(date, ip, hostname, mac_address, open_ports):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (date, ip, hostname, mac_address, open_ports) VALUES (?, ?, ?, ?, ?)",
                   (date, ip, hostname, mac_address, open_ports))
    conn.commit()
    conn.close()


# Retrieve past scans from the database
def load_past_scans():
    # Clear previous results
    for row_id in results_tree.get_children():
        results_tree.delete(row_id)

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT date, ip, hostname, mac_address, open_ports FROM scans")
    rows = cursor.fetchall()
    conn.close()
    for row in rows:
        results_tree.insert("", "end", values=row)


# Function to scan a single IP
def scan_ip(ip):
    try:
        # Get the current date and time
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Send ICMP packet to check if host is up
        packet = IP(dst=str(ip)) / ICMP()
        response = sr1(packet, timeout=1, verbose=0)

        if response is not None:
            # Gather device information if host is up
            result = {"Date": date, "IP": str(ip)}

            # Get hostname
            try:
                result["Hostname"] = nm.scan(hosts=str(ip), arguments='-sn')['scan'][str(ip)]['hostnames'][0]['name']
            except:
                result["Hostname"] = "Unknown"

            # Get MAC address using ARP
            arp_response = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip)), timeout=1, verbose=0)
            result["MAC Address"] = arp_response.hwsrc if arp_response else "Unknown"

            # Scan open ports on the device
            open_ports = []
            port_scan = nm.scan(str(ip), '20-1024')
            for port in port_scan['scan'][str(ip)]['tcp']:
                if port_scan['scan'][str(ip)]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
            result["Open Ports"] = ", ".join(map(str, open_ports))

            # Save the scan result to the database with the date
            save_scan(result["Date"], result["IP"], result["Hostname"], result["MAC Address"], result["Open Ports"])

            # Insert the result into the Treeview with the date
            results_tree.insert("", "end", values=(
            result["Date"], result["IP"], result["Hostname"], result["MAC Address"], result["Open Ports"]))
    except Exception as e:
        print(f"Error scanning {ip}: {e}")


# Function to scan the subnet
def scan_subnet():
    subnet = subnet_entry.get()
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
    except ValueError:
        display_output("Invalid subnet. Please enter a valid subnet (e.g., 192.168.1.0/24).")


# GUI setup
root = tk.Tk()
root.title("Advanced IP Scanner - Python with History")
root.geometry("800x500")

# Subnet entry
tk.Label(root, text="Enter Subnet (e.g., 192.168.1.0/24):").pack(pady=10)
subnet_entry = tk.Entry(root, width=30)
subnet_entry.pack(pady=5)

# Buttons for scanning and viewing history
scan_button = tk.Button(root, text="Scan Subnet", command=scan_subnet)
scan_button.pack(pady=5)
load_history_button = tk.Button(root, text="Load Past Scans", command=load_past_scans)
load_history_button.pack(pady=5)

# Results table
columns = ("Date", "IP Address", "Hostname", "MAC Address", "Open Ports")
results_tree = ttk.Treeview(root, columns=columns, show="headings")

# Set column widths and alignments
results_tree.column("Date", anchor="center", width=150, stretch=True)
results_tree.column("IP Address", anchor="center", width=100, stretch=True)
results_tree.column("Hostname", anchor="center", width=150, stretch=True)
results_tree.column("MAC Address", anchor="center", width=150, stretch=True)
results_tree.column("Open Ports", anchor="center", width=150, stretch=True)

# Set column headings
for col in columns:
    results_tree.heading(col, text=col, anchor="center")
results_tree.pack(fill="both", expand=True, padx=10, pady=10)

# Initialize the database
setup_database()

# Start the GUI main loop
root.mainloop()
