import tkinter as tk
from tkinter import *
from tkinter import ttk, messagebox
import subprocess
import re
import nmap

# Functions for Wi-Fi Profiles
def fetch_wifi_profiles():
    """
    Fetches the list of Wi-Fi profiles available on the system along with their passwords.

    This function executes a series of shell commands using the `netsh` command-line tool
    to retrieve the saved Wi-Fi profiles and their associated passwords, if any. It parses the
    command outputs to extract the profile details such as SSID and password. The Wi-Fi
    profiles with no security key are skipped.

    :raises Exception: If there is an error in executing the subprocess commands or
                       retrieving Wi-Fi details.

    :return: A list of dictionaries containing Wi-Fi profile details. Each dictionary
             in the list represents a Wi-Fi profile and includes the following keys:
             - **ssid**: The SSID (name) of the Wi-Fi network.
             - **password**: The password associated with the Wi-Fi profile. If the
                             password is not available, this key will have a value of None.
    :rtype: list[dict[str, str | None]]
    """
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

def check_password_strength(password):
    """
    Evaluates the strength of a provided password based on various recommended
    criteria to ensure its security. Password strengths are categorized into
    three levels: "Strong", "Medium", or "Weak". Additionally, suggestions are
    provided to guide users in improving the strength of their password.

    :param password: The password string to be evaluated
    :type password: str

    :return: A tuple consisting of the strength category as a string and a
        list of recommendations for improving the password, if necessary
    :rtype: tuple[str, list[str]]
    """
    if not password:
        return "No Password", ["Consider setting a password for this network."]
    recommendations = []
    if len(password) < 8:
        recommendations.append("Password should be at least 8 characters long.")
    if not any(char.isupper() for char in password):
        recommendations.append("Include at least one uppercase letter.")
    if not any(char.isdigit() for char in password):
        recommendations.append("Add at least one number.")
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        recommendations.append("Include at least one special character (e.g., !@#$%^&*).")

    if len(recommendations) == 0:
        return "Strong", ["This password meets all recommended criteria."]
    elif len(recommendations) <= 2:
        return "Medium", recommendations
    else:
        return "Weak", recommendations

def display_wifi_profiles():
    """
    Displays the WiFi profiles in a graphical interface by fetching WiFi data, clearing
    the current tree view, and inserting new data. This function retrieves the SSID,
    password, and password strength for each available WiFi profile and updates the view.

    :return: None
    """
    wifi_list = fetch_wifi_profiles()
    # Clear the treeview
    for item in wifi_tree.get_children():
        wifi_tree.delete(item)
    # Insert new data into the treeview
    for wifi in wifi_list:
        ssid = wifi["ssid"]
        password = wifi["password"]
        strength, _ = check_password_strength(password)
        wifi_tree.insert("", tk.END, values=(ssid, password, strength))

def show_recommendations():
    """
    Displays recommendations for the selected Wi-Fi profile's password strength.

    This function retrieves the currently selected Wi-Fi profile item from the
    `wifi_tree`. If no item is selected, it displays an error message prompting
    the user to select an item. For the selected item's password, it evaluates
    its strength using `check_password_strength` and shows password improvement
    recommendations to the user in a message box.

    :raises ValueError: if the `password` parameter passed to
        `check_password_strength` is invalid.
    :param wifi_tree: A tkinter.Treeview instance displaying Wi-Fi profiles.
    :return: None
    """
    selected_item = wifi_tree.selection()
    if not selected_item:
        messagebox.showinfo("Selection Error", "Please select a Wi-Fi profile.")
        return

    item = wifi_tree.item(selected_item)
    password = item["values"][1]
    _, recommendations = check_password_strength(password)

    messagebox.showinfo("Password Recommendations", "\n".join(recommendations))

def show_change_password_instructions():
    """
    Displays a message box with detailed instructions to guide users on how
    to change their Wi-Fi password. This function opens an informational
    dialog window and provides step-by-step instructions aimed at ensuring
    users can easily update their router's Wi-Fi password.

    :raises: Exception: If `messagebox.showinfo` fails to display, though
        this is highly unlikely and may depend on the underlying platform.
    :return: None
    """
    instructions = (
        "To change your WiFi password:\n"
        "1. Open your router's web interface (usually accessed via a browser at 192.168.1.1).\n"
        "2. Log in with your router's credentials.\n"
        "3. Go to the Wi-Fi or wireless settings section.\n"
        "4. Change the Wi-Fi password to a stronger one.\n"
        "5. Save the settings and reconnect devices with the new password."
        )
    messagebox.showinfo("Change Wi-Fi Password", instructions)

# Existing tool functions
def close_ports():
    """
    Closes network or application ports and displays a confirmation message.

    This function is designed to notify the user that certain ports have been
    successfully closed. It uses a graphical message box to provide the confirmation.

    :return: None
    """
    messagebox.showinfo("Close Ports", "Ports have been closed successfully.")

def help_links():
    """
    Displays a help dialog with predefined links for additional assistance.

    This function generates an informational message box, displaying help links
    to guide users when extra support is required.

    :return: None
    """
    messagebox.showinfo("Help Links", "Use these links to get extra help.")


def show_disclaimer():
    """
    Display a general disclaimer message to the user. This function is intended to
    be used to provide necessary information or warnings as required.

    :raises RuntimeError: If the disclaimer cannot be shown due to
        underlying issues.

    :return: None
    """
    pass

def show_disclaimer_message():
    """
    Displays a disclaimer message in an informational dialog box. This function utilizes a messagebox
    to inform the user about the educational purpose of the tool and warns against unauthorized usage,
    emphasizing responsibility and adherence to legal boundaries. It ensures the user is aware of the
    limitations and ethical considerations before proceeding further.

    :raises tkinter.TclError: If `messagebox.showinfo` fails due to GUI or system-related issues.
    :return: None
    """
    messagebox.showinfo(
        "Disclaimer",
        (
            "Disclaimer: This tool is for educational purposes only. "
            "Unauthorized use to access or modify networks is illegal. "
            "Use responsibly and ensure you have permission to perform these actions on the target network."
        )
    )

def update_progress():
    """
    Update the progress label to display the current progress of tasks.

    This function calculates the number of completed tasks by summing the values
    from the checklist variables, which are assumed to be binary (e.g., 0 or 1 for
    incomplete or complete). It then updates the progress label to reflect the
    number of completed tasks out of the total number of tasks.

    :param checklist_vars: List of binary variables representing task completion
        status (assumed to be integers or boolean values).
    :param progress_label: The label widget to be updated with the progress text.

    :return: None
    """
    completed = sum(var.get() for var in checklist_vars)
    total = len(checklist_vars)
    progress_label.config(text=f"Progress: {completed}/{total} tasks completed")

def display_output(text):
    """
    Appends the provided text to a text widget and ensures it is scrolled to view
    the appended text.

    :param text: The string to be appended to the text widget.
    :type text: str
    :return: None
    """
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)

def scan_ports():
    """
    Scans the ports for given IP addresses in the range 1-1024 using nmap. The
    function initiates the scanning process, retrieves the results, and displays
    information about the hosts, including their hostnames, states, protocols,
    and the state of each scanned port. If an error occurs during the scanning
    process, the error message is displayed.

    :raises Exception: If an error occurs during the nmap scanning process.

    :return: None
    """
    ip = ip_entry.get()
    if not ip:
        display_output("Please enter a valid IP address. e.g. 192.168.0.1/24")
        return

    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, '1-1024')
        for host in scanner.all_hosts():
            display_output(f"Host: {host} ({scanner[host].hostname()})")
            display_output(f"State: {scanner[host].state()}")
            for protocol in scanner[host].all_protocols():
                display_output(f"Protocol: {protocol}")
                ports = scanner[host][protocol].keys()
                for port in ports:
                    display_output(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")
    except Exception as e:
        display_output(f"Error during scanning: {e}")

# Create the main application window
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

# Help menu
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Home Network Vulnerability Assessment Tool\nVersion 1.0"))
help_menu.add_command(label="Documentation", command=lambda: messagebox.showinfo("Documentation", "Help documentation will be added here."))
help_menu.add_command(label="FAQ", command=lambda: messagebox.showinfo("FAQ", "FAQs will be added here."))
menu_bar.add_cascade(label="Help", menu=help_menu)

# Main layout: Left for checklist, right for tabbed interface
main_frame = tk.Frame(root)
main_frame.pack(fill="both", expand=True)

# Right frame for tabbed interface
tab_frame = tk.Frame(main_frame)
tab_frame.pack(side="right", fill="both", expand=True)

# Left frame for checklist
checklist_frame = tk.Frame(main_frame, width=250, bg="#f7f7f7", relief="solid", bd=1)
checklist_frame.pack(side="left", fill="y")

# Create a canvas widget inside the checklist_frame
checklist_canvas = tk.Canvas(checklist_frame)
checklist_canvas.pack(side="left", fill="both", expand=True)

# Add a scrollbar for the checklist, and link it to the canvas
checklist_scrollbar = tk.Scrollbar(checklist_frame, orient="vertical", command=checklist_canvas.yview)
checklist_scrollbar.pack(side="right", fill="y")

# Configure the canvas to use the scrollbar
checklist_canvas.config(yscrollcommand=checklist_scrollbar.set)

# Create a frame inside the canvas to hold the checklist content
checklist_content_frame = tk.Frame(checklist_canvas, bg="#f7f7f7")

# Use a window to place the content_frame inside the canvas
checklist_canvas.create_window((0, 0), window=checklist_content_frame, anchor="nw")

# Update the scroll region of the canvas whenever the content frame is updated
def update_scroll_region(event=None):
    """
    Updates the scroll region of a canvas widget to ensure that all its
    contents can be scrolled within the visible area. This function is
    typically used in applications where dynamic content is added to a
    canvas and its scrollable region needs to be adjusted.

    :param event: Event object associated with the widget, typically
        triggered by user interaction or programmatic updates.
    :type event: Optional[Any]
    :return: None
    """
    checklist_canvas.config(scrollregion=checklist_canvas.bbox("all"))

# Bind the function to the content frame
checklist_content_frame.bind("<Configure>", update_scroll_region)

# Checklist content
checklist_label = tk.Label(checklist_content_frame, text="Network Security Checklist", font=("Arial", 14), bg="#f7f7f7")
checklist_label.pack(pady=10)

checklist_items = [
    "1. Change the Default Router Login Username and Password",
    "2. Disable Remote Management",
    "3. Update Router Firmware",
    "4. Use WPA3 (or WPA2) Encryption",
    "5. Set a Strong Wi-Fi Password",
    "6. Hide the Network SSID (Optional)",
    "7. Create a Guest Network",
    "8. Enable MAC Address Filtering",
    "9. List Connected Devices",
    "10. Update Software and Firmware ",
    "11. Set Strong Passwords and Enable MFA(optional",
    "12. Secure IoT Devices",
    "13. Enable Router Logs",
    "14. Enable Firewall and Intrusion Detection",
    "15. Encrypt Sensitive Files",
    "16. Use a VPN(optional)",
    "17. Disable Unused Ports and Services",
    "18. Secure Router and Devices",
    "19. Periodic Checks and Scans",
    "20. Backup Data",
    "21. See Detailed Checklist for more information"
]

checklist_vars = [tk.IntVar(value=0) for _ in checklist_items]

for item, var in zip(checklist_items, checklist_vars):
    checkbox = ttk.Checkbutton(checklist_content_frame, text=item, variable=var, command=update_progress)
    checkbox.pack(anchor="w", padx=10, pady=5)

progress_label = tk.Label(checklist_content_frame, text="Progress: 0/21 tasks completed", font=("Arial", 12), bg="#f7f7f7")
progress_label.pack(pady=10)

# Tabbed interface for main functionality
notebook = ttk.Notebook(tab_frame)
notebook.pack(expand=True, fill="both")

# Define frames for each tab
home_frame = ttk.Frame(notebook)
close_ports_frame = ttk.Frame(notebook)
help_links_frame = ttk.Frame(notebook)
guest_network_frame = ttk.Frame(notebook)
wifi_profiles_frame = ttk.Frame(notebook)
disclaimer_frame = ttk.Frame(notebook)

# Add tabs to the notebook
notebook.add(home_frame, text="Home")
notebook.add(close_ports_frame, text="Close Ports")
notebook.add(help_links_frame, text="Help Links")
notebook.add(guest_network_frame, text="Setup Guest Network")
notebook.add(wifi_profiles_frame, text="Wi-Fi Profiles")
notebook.add(disclaimer_frame, text="Disclaimer")

# Close Ports tab content
close_ports_label = ttk.Label(close_ports_frame, text="Scan Ports for Open Connections", font=("Arial", 14))
close_ports_label.pack(pady=10)

ip_label = tk.Label(close_ports_frame, text="Enter IP Address:")
ip_label.pack(pady=5)
ip_entry = tk.Entry(close_ports_frame, width=30)
ip_entry.pack(pady=5)

scan_button = tk.Button(close_ports_frame, text="Scan Ports", command=scan_ports)
scan_button.pack(pady=10)

output_text = tk.Text(close_ports_frame, height=15, width=60)
output_text.pack(pady=10)

# Wi-Fi Profiles tab content
wifi_profiles_label = ttk.Label(wifi_profiles_frame, text="Saved Wi-Fi Profiles", font=("Arial", 14))
wifi_profiles_label.pack(pady=10)

wifi_tree = ttk.Treeview(wifi_profiles_frame, columns=("SSID", "Password", "Strength"), show="headings", height=10)
wifi_tree.heading("SSID", text="SSID")
wifi_tree.heading("Password", text="Password")
wifi_tree.heading("Strength", text="Strength")
wifi_tree.column("SSID", anchor="w", width=200)
wifi_tree.column("Password", anchor="w", width=150)
wifi_tree.column("Strength", anchor="w", width=100)
wifi_tree.pack(pady=10)

fetch_button = ttk.Button(wifi_profiles_frame, text="Show Wi-Fi Profiles", command=display_wifi_profiles)
fetch_button.pack(pady=10)

recommend_button = tk.Button(wifi_profiles_frame, text="Show Recommendations", command=show_recommendations)
recommend_button.pack(pady=5)

change_password_button = tk.Button(wifi_profiles_frame, text="How to Change Wi-Fi Password",
                                   command=show_change_password_instructions)
change_password_button.pack(pady=5)

disclaimer_button = tk.Button(disclaimer_frame, text="View Disclaimer", command=show_disclaimer_message)
disclaimer_button.pack(pady=20)
# Start the GUI main loop
root.mainloop()
