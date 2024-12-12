import subprocess
import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


def fetch_wifi_profiles():
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


def display_wifi_profiles():
    wifi_list = fetch_wifi_profiles()
    # Clear the treeview
    for item in tree.get_children():
        tree.delete(item)
    # Insert new data into the treeview
    for wifi in wifi_list:
        ssid = wifi["ssid"]
        password = wifi["password"]
        tree.insert("", tk.END, values=(ssid, password))

# Setting up the main tkinter window
root = tk.Tk()
root.title("Wi-Fi Profile Viewer")
root.geometry("500x400")

# Label and Listbox to display Wi-Fi profiles
label = tk.Label(root, text="Saved Wi-Fi Profiles")
label.pack(pady=10)

# Treeview for displaying Wi-Fi profiles in columns
tree = ttk.Treeview(root, columns=("SSID", "Password"), show="headings", height=10)
tree.heading("SSID", text="SSID")
tree.heading("Password", text="Password")
tree.column("SSID", anchor="w", width=200)
tree.column("Password", anchor="w", width=150)
tree.pack(pady=10)

# Fetch and display Wi-Fi profiles on button click
button = tk.Button(root, text="Show Wi-Fi Profiles", command=display_wifi_profiles)
button.pack(pady=10)

root.mainloop()
