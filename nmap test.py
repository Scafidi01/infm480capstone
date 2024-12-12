import tkinter as tk
from tkinter import ttk
import nmap

# Create the main window
root = tk.Tk()
root.title("Home Network Vulnerability Scanner")
root.geometry("400x400")  # Set the window size

# Create a label
label = tk.Label(root, text="Enter the IP address:")
label.pack(pady=10)

# Create a text entry box for IP input
ip_entry = tk.Entry(root)
ip_entry.pack(pady=5)

# Create a text box to display results
output_text = tk.Text(root, height=15, width=50)
output_text.pack(pady=10)

# Function to update the output_text widget
def display_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

# Function to scan ports
def scan_ports():
    ip = ip_entry.get()
    if not ip:
        display_output("Please enter a valid IP address.")
        return

    # Nmap scanning code
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024')  # Scan ports 1-1024
    for host in scanner.all_hosts():
        display_output(f"Host: {host} ({scanner[host].hostname()})")
        display_output(f"State: {scanner[host].state()}")
        for protocol in scanner[host].all_protocols():
            display_output(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in ports:
                display_output(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")

# Create a button to trigger the port scan
scan_button = tk.Button(root, text="Scan Ports", command=scan_ports)
scan_button.pack(pady=5)

# Run the GUI main loop
root.mainloop()
