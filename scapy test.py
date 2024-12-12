import tkinter as tk
from scapy.all import sr1, IP, ICMP
import ipaddress

# Function to scan the subnet and display active devices
def scan_subnet():
    subnet = subnet_entry.get()  # Get the subnet from user input
    try:
        # Validate subnet input
        network = ipaddress.ip_network(subnet, strict=False)
        display_output(f"Scanning subnet: {subnet}")

        # Scan each host in the subnet
        for ip in network.hosts():
            packet = IP(dst=str(ip))/ICMP()  # Create an ICMP packet for each IP
            response = sr1(packet, timeout=1, verbose=0)  # Send the packet

            if response is not None:  # If there's a response, IP is active
                display_output(f"Device found at IP: {ip}")

    except ValueError:
        display_output("Invalid subnet. Please enter a valid subnet (e.g., 192.168.1.0/24).")

# Function to update output in the text box
def display_output(text):
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)  # Scroll to the end of the output

# Clear the output text box
def clear_output():
    output_text.delete("1.0", tk.END)

# Set up the main application window
root = tk.Tk()
root.title("Subnet Scanner")
root.geometry("500x400")

# Label and entry for subnet input
tk.Label(root, text="Enter Subnet (e.g., 192.168.1.0/24):").pack(pady=10)
subnet_entry = tk.Entry(root, width=30)
subnet_entry.pack(pady=5)

# Output text box for displaying scan results
output_text = tk.Text(root, height=15, width=60)
output_text.pack(pady=10)

# Buttons to start scan and clear output
scan_button = tk.Button(root, text="Scan Subnet", command=scan_subnet)
scan_button.pack(pady=5)

clear_button = tk.Button(root, text="Clear Output", command=clear_output)
clear_button.pack(pady=5)

# Start the GUI event loop
root.mainloop()

