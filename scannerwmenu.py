import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sr1, IP, ICMP, ARP, Ether
import ipaddress
import threading
import nmap
import sqlite3
import datetime


class AdvancedIPScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IP Scanner")
        self.root.geometry("900x600")

        # Initialize Nmap
        self.nm = nmap.PortScanner()

        # Setup database
        self.setup_database()

        # Initialize GUI components
        self.create_menu()
        self.create_main_frame()

    def setup_database(self):
        """Set up SQLite database for scan history."""
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

    def save_scan(self, date, ip, hostname, mac_address, open_ports):
        """Save scan results to the database."""
        conn = sqlite3.connect("scans.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (date, ip, hostname, mac_address, open_ports) VALUES (?, ?, ?, ?, ?)",
                       (date, ip, hostname, mac_address, open_ports))
        conn.commit()
        conn.close()

    def create_menu(self):
        """Create the application menu."""
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

    def show_about(self):
        """Show information about the application."""
        messagebox.showinfo("About", "Advanced IP Scanner\nVersion 1.0\nCreated with Python")

    def create_main_frame(self):
        """Create the main application frame."""
        # Main frame with tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        # Scan tab
        self.scan_frame = ttk.Frame(notebook)
        notebook.add(self.scan_frame, text="Scan Subnet")
        self.create_scan_tab()

        # History tab
        self.history_frame = ttk.Frame(notebook)
        notebook.add(self.history_frame, text="Scan History")
        self.create_history_tab()

    def create_scan_tab(self):
        """Create the scan subnet tab."""
        tk.Label(self.scan_frame, text="Enter Subnet (e.g., 192.168.1.0/24):").pack(pady=10)
        self.subnet_entry = tk.Entry(self.scan_frame, width=30)
        self.subnet_entry.pack(pady=5)
        tk.Button(self.scan_frame, text="Scan Subnet", command=self.scan_subnet).pack(pady=5)

    def create_history_tab(self):
        """Create the scan history tab."""
        tk.Button(self.history_frame, text="Load Past Scans", command=self.load_past_scans).pack(pady=10)

        columns = ("Date", "IP Address", "Hostname", "MAC Address", "Open Ports")
        self.results_tree = ttk.Treeview(self.history_frame, columns=columns, show="headings")

        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, anchor="center", width=150)

        self.results_tree.pack(fill="both", expand=True)

    def scan_ip(self, ip):
        """Scan a single IP address."""
        # Your scan logic goes here
        pass  # Replace with actual scanning code

    def scan_subnet(self):
        """Scan a subnet."""
        subnet = self.subnet_entry.get()
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            for ip in network.hosts():
                thread = threading.Thread(target=self.scan_ip, args=(ip,))
                thread.start()
        except ValueError:
            messagebox.showerror("Error", "Invalid subnet. Please enter a valid subnet (e.g., 192.168.1.0/24).")

    def load_past_scans(self):
        """Load past scans from the database."""
        for row_id in self.results_tree.get_children():
            self.results_tree.delete(row_id)

        conn = sqlite3.connect("scans.db")
        cursor = conn.cursor()
        cursor.execute("SELECT date, ip, hostname, mac_address, open_ports FROM scans")
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            self.results_tree.insert("", "end", values=row)


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedIPScanner(root)
    root.mainloop()
