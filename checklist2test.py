import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import nmap  # Ensure nmap is installed (`pip install python-nmap`)
import os

# Guest Wi-Fi Network Setup Function
def setup_guest_wifi():
    """Show the guest Wi-Fi setup steps in a popup dialog."""
    def proceed_to_next_step(step):
        """Proceed to the next step in the setup process."""
        if step < len(steps):
            step_label.config(text=steps[step]["text"])
            if steps[step]["input"]:
                input_field.pack(pady=5)
                next_button.config(command=lambda: capture_input(step))
            else:
                input_field.pack_forget()
                next_button.config(command=lambda: proceed_to_next_step(step + 1))
        else:
            # Summary
            step_label.config(text=f"Guest Wi-Fi Setup Completed!\n\n")
            input_field.pack_forget()
            next_button.pack_forget()
            close_button.pack(pady=10)

    def capture_input(step):
        """Capture input for SSID or password."""
        user_input = input_field.get()
        field_name = steps[step]["field"]
        if field_name:
            guest_info[field_name] = user_input
        input_field.delete(0, tk.END)
        proceed_to_next_step(step + 1)

    # Create the popup dialog
    popup = tk.Toplevel(root)
    popup.title("Steps for Guest Wi-Fi Setup")
    popup.geometry("400x300")

    guest_info = {}
    steps = [
        {"text": "Important Note! Ensure you follow these steps in your router's admin panel to complete the setup.", "input": False, "field": None},
        {"text": "Step 1: Log into your router's admin panel.\n\n"
                 "- Open a web browser.\n"
                 "- Enter your router's IP address (e.g., 192.168.1.1).\n"
                 "- Log in with your admin credentials.", "input": False, "field": None},
        {"text": "Step 2: Navigate to the wireless or Wi-Fi settings.\n\n"
                 "- Look for an option labeled 'Guest Network' or similar.", "input": False, "field": None},
        {"text": "Step 3 (Optional): Restrict guest network access.\n\n"
                 "- Limit guest access to the internet only.\n"
                 "- Configure bandwidth limits for guests.", "input": False, "field": None},
    ]

    # UI Elements in Popup
    step_label = tk.Label(popup, text=steps[0]["text"], wraplength=350, justify="left")
    step_label.pack(pady=10)

    input_field = tk.Entry(popup, width=30)
    next_button = tk.Button(popup, text="Next", command=lambda: proceed_to_next_step(0))
    next_button.pack(pady=10)

    close_button = tk.Button(popup, text="Close", command=popup.destroy)
    close_button.pack_forget()  # Hide the button until the last step

    proceed_to_next_step(0)

# Existing tool functions (abbreviated for brevity)
def close_ports():
    messagebox.showinfo("Close Ports", "Ports have been closed successfully.")

def change_passwords():
    messagebox.showinfo("Change Passwords", "Passwords have been changed successfully.")

def show_disclaimer():
    disclaimer_text = (
        "Disclaimer: This tool is for educational purposes only. "
        "Unauthorized use to access or modify networks is illegal. "
        "Use responsibly and ensure you have permission to perform these actions on the target network."
    )
    messagebox.showinfo("Disclaimer", disclaimer_text)

# Main application setup
root = tk.Tk()
root.title("Home Network Vulnerability Assessment Tool")
root.geometry("900x600")

# Menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# File menu
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

# Main layout: Left for checklist, right for tabbed interface
main_frame = tk.Frame(root)
main_frame.pack(fill="both", expand=True)

# Left frame for checklist
checklist_frame = tk.Frame(main_frame, width=250, bg="#f7f7f7", relief="solid", bd=1)
checklist_frame.pack(side="left", fill="y")

# Right frame for tabbed interface
tab_frame = tk.Frame(main_frame)
tab_frame.pack(side="right", fill="both", expand=True)

# Checklist content (abbreviated for brevity)

# Tabbed interface for main functionality
notebook = ttk.Notebook(tab_frame)
notebook.pack(expand=True, fill="both")

# Guest Network Setup tab
guest_network_frame = ttk.Frame(notebook)
notebook.add(guest_network_frame, text="Setup Guest Network")

# Guest Network Setup tab content
guest_network_label = ttk.Label(guest_network_frame, text="Setup Guest Network for IoT Devices", font=("Arial", 14))
guest_network_label.pack(pady=10)

guest_network_button = ttk.Button(guest_network_frame, text="Setup Guest Wi-Fi", command=setup_guest_wifi)
guest_network_button.pack(pady=10)

# Start the GUI main loop
root.mainloop()
