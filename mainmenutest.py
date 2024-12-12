import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# Define each function for the tool
def close_ports():
    messagebox.showinfo("Close Ports", "Closing ports...")  # Placeholder action
    # Add actual port closing logic here

def change_passwords():
    messagebox.showinfo("Change Passwords", "Changing passwords...")  # Placeholder action
    # Add actual password changing logic here

def setup_guest_network():
    messagebox.showinfo("Set Up Guest Network", "Setting up guest network for IoT devices...")  # Placeholder action
    # Add actual guest network setup logic here

# Create the main application window
root = tk.Tk()
root.title("Home Network Vulnerability Assessment Tool")
root.geometry("400x300")

# Create a notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# Define frames for each tab
close_ports_frame = ttk.Frame(notebook)
change_passwords_frame = ttk.Frame(notebook)
guest_network_frame = ttk.Frame(notebook)

# Add tabs to the notebook
notebook.add(close_ports_frame, text="Close Ports")
notebook.add(change_passwords_frame, text="Change Passwords")
notebook.add(guest_network_frame, text="Setup Guest Network")

# Close Ports tab content
close_ports_label = ttk.Label(close_ports_frame, text="Close Ports Functionality", font=("Arial", 14))
close_ports_label.pack(pady=10)
close_ports_button = ttk.Button(close_ports_frame, text="Execute", command=close_ports)
close_ports_button.pack()

# Change Passwords tab content
change_passwords_label = ttk.Label(change_passwords_frame, text="Change Passwords Functionality", font=("Arial", 14))
change_passwords_label.pack(pady=10)
change_passwords_button = ttk.Button(change_passwords_frame, text="Execute", command=change_passwords)
change_passwords_button.pack()

# Guest Network Setup tab content
guest_network_label = ttk.Label(guest_network_frame, text="Setup Guest Network for IoT", font=("Arial", 14))
guest_network_label.pack(pady=10)
guest_network_button = ttk.Button(guest_network_frame, text="Execute", command=setup_guest_network)
guest_network_button.pack()

# Start the GUI main loop
root.mainloop()
