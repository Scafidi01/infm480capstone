import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import nmap
import sqlite3
import datetime
from scapy.all import sr1, IP, ICMP, ARP, Ether
import ipaddress
import threading

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
    for row_id in results_tree.get_children():
        results_tree.delete(row_id)

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT date, ip, hostname, mac_address, open_ports FROM scans")
    rows = cursor.fetchall()
    conn.close()
    for row in rows:
        results_tree.insert("", "end", values=row)

# Functions for scanning and displaying results
def scan_ip(ip):
    try:
        date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet = IP(dst=str(ip)) / ICMP()
        response = sr1(packet, timeout=1, verbose=0)

        if response is not None:
            result = {"Date": date, "IP": str(ip)}
            try:
                result["Hostname"] = nm.scan(hosts=str(ip), arguments='-sn')['scan'][str(ip)]['hostnames'][0]['name']
            except:
                result["Hostname"] = "Unknown"

            arp_response = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip)), timeout=1, verbose=0)
            result["MAC Address"] = arp_response.hwsrc if arp_response else "Unknown"

            open_ports = []
            port_scan = nm.scan(str(ip), '20-1024')
            for port in port_scan['scan'][str(ip)]['tcp']:
                if port_scan['scan'][str(ip)]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
            result["Open Ports"] = ", ".join(map(str, open_ports))

            save_scan(result["Date"], result["IP"], result["Hostname"], result["MAC Address"], result["Open Ports"])
            results_tree.insert("", "end", values=(
                result["Date"], result["IP"], result["Hostname"], result["MAC Address"], result["Open Ports"]))
    except Exception as e:
        print(f"Error scanning {ip}: {e}")

def scan_subnet():
    subnet = subnet_entry.get()
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
    except ValueError:
        messagebox.showerror("Error", "Invalid subnet. Please enter a valid subnet (e.g., 192.168.1.0/24).")

# Functions for Wi-Fi profiles
def fetch_wifi_profiles():
    try:
        command_output = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True).stdout.decode()
        profile_names = re.findall("All User Profile     : (.*)\r", command_output)
        wifi_list = []
        if profile_names:
            for name in profile_names:
                wifi_profile = {}
                profile_info = subprocess.run(["netsh", "wlan", "show", "profile", name],
                                              capture_output=True).stdout.decode()
                if re.search("Security key           : Absent", profile_info):
                    continue
                else:
                    wifi_profile["ssid"] = name
                    profile_info_pass = subprocess.run(["netsh", "wlan", "show", "profile", name, "key=clear"],
                                                       capture_output=True).stdout.decode()
                    password = re.search("Key Content            : (.*)\r", profile_info_pass)
                    wifi_profile["password"] = password[1] if password else None
                    wifi_list.append(wifi_profile)
        return wifi_list
    except Exception as e:
        messagebox.showerror("Error", f"Failed to fetch Wi-Fi profiles: {e}")
        return []

def display_wifi_profiles():
    wifi_list = fetch_wifi_profiles()
    for item in wifi_tree.get_children():
        wifi_tree.delete(item)
    for wifi in wifi_list:
        ssid = wifi["ssid"]
        password = wifi["password"]
        wifi_tree.insert("", tk.END, values=(ssid, password))

# GUI setup
root = tk.Tk()
root.title("Unified Network Security Tool")
root.geometry("1000x700")

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Unified Network Security Tool\nVersion 1.0"))
menu_bar.add_cascade(label="Help", menu=help_menu)

main_frame = tk.Frame(root)
main_frame.pack(fill="both", expand=True)

checklist_frame = tk.Frame(main_frame, width=250, bg="#f7f7f7", relief="solid", bd=1)
checklist_frame.pack(side="left", fill="y")

tab_frame = tk.Frame(main_frame)
tab_frame.pack(side="right", fill="both", expand=True)

checklist_label = tk.Label(checklist_frame, text="Security Checklist", font=("Arial", 14), bg="#f7f7f7")
checklist_label.pack(pady=10)

checklist_items = [
    "Use strong passwords",
    "Update firmware",
    "Enable router firewall",
    "Monitor unusual activity",
    "Separate IoT devices"
]

checklist_vars = [tk.IntVar(value=0) for _ in checklist_items]
for item, var in zip(checklist_items, checklist_vars):
    checkbox = ttk.Checkbutton(checklist_frame, text=item, variable=var)
    checkbox.pack(anchor="w", padx=10, pady=5)

notebook = ttk.Notebook(tab_frame)
notebook.pack(expand=True, fill="both")

subnet_scan_frame = ttk.Frame(notebook)
wifi_profiles_frame = ttk.Frame(notebook)

notebook.add(subnet_scan_frame, text="Scan Subnet")
notebook.add(wifi_profiles_frame, text="Wi-Fi Profiles")

# Subnet scanning tab
subnet_label = tk.Label(subnet_scan_frame, text="Enter Subnet (e.g., 192.168.1.0/24):")
subnet_label.pack(pady=10)
subnet_entry = tk.Entry(subnet_scan_frame, width=30)
subnet_entry.pack(pady=5)
scan_button = tk.Button(subnet_scan_frame, text="Scan", command=scan_subnet)
scan_button.pack(pady=10)

columns = ("Date", "IP", "Hostname", "MAC", "Open Ports")
results_tree = ttk.Treeview(subnet_scan_frame, columns=columns, show="headings")
for col in columns:
    results_tree.heading(col, text=col)
    results_tree.column(col, width=150)
results_tree.pack(fill="both", expand=True)

# Wi-Fi profiles tab
wifi_label = tk.Label(wifi_profiles_frame, text="Saved Wi-Fi Profiles", font=("Arial", 14))
wifi_label.pack(pady=10)
columns = ("SSID", "Password")
wifi_tree = ttk.Treeview(wifi_profiles_frame, columns=columns, show="headings")
for col in columns:
    wifi_tree.heading(col, text=col)
    wifi_tree.column(col, width=150)
wifi_tree.pack(fill="both", expand=True)

fetch_button = ttk.Button(wifi_profiles_frame, text="Fetch Wi-Fi Profiles", command=display_wifi_profiles)
fetch_button.pack(pady=10)

setup_database()
root.mainloop()
