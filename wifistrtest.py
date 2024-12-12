import subprocess
import re
import tkinter as tk
from tkinter import messagebox, ttk


# Function to fetch Wi-Fi profiles and passwords
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


# Function to check password strength
def check_password_strength(password):
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


# Function to display Wi-Fi profiles and their password strengths
def display_wifi_profiles():
    wifi_list = fetch_wifi_profiles()
    # Clear the treeview
    for item in tree.get_children():
        tree.delete(item)
    # Insert new data into the treeview
    for wifi in wifi_list:
        ssid = wifi["ssid"]
        password = wifi["password"]
        strength, recommendations = check_password_strength(password)
        tree.insert("", tk.END, values=(ssid, password, strength))


# Function to show recommendations for selected Wi-Fi profile
def show_recommendations():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showinfo("Selection Error", "Please select a Wi-Fi profile.")
        return

    item = tree.item(selected_item)
    password = item["values"][1]
    _, recommendations = check_password_strength(password)

    messagebox.showinfo("Password Recommendations", "\n".join(recommendations))


# Function to show instructions on changing Wi-Fi password
def show_change_password_instructions():
    instructions = (
        "To change your WiFi password:\n"
        "1. Open your router's web interface (usually accessed via a browser at 192.168.1.1).\n"
        "2. Log in with your router's credentials.\n"
        "3. Go to the Wi-Fi or wireless settings section.\n"
        "4. Change the Wi-Fi password to a stronger one.\n"
        "5. Save the settings and reconnect devices with the new password."
    )
    messagebox.showinfo("Change Wi-Fi Password", instructions)


# Setting up the main tkinter window
root = tk.Tk()
root.title("Wi-Fi Profile Viewer and Password Strength Checker")
root.geometry("600x500")

# Label and Treeview to display Wi-Fi profiles
label = tk.Label(root, text="Saved Wi-Fi Profiles", font=("Arial", 14))
label.pack(pady=10)

tree = ttk.Treeview(root, columns=("SSID", "Password", "Strength"), show="headings", height=10)
tree.heading("SSID", text="SSID")
tree.heading("Password", text="Password")
tree.heading("Strength", text="Strength")
tree.column("SSID", anchor="w", width=200)
tree.column("Password", anchor="w", width=150)
tree.column("Strength", anchor="w", width=100)
tree.pack(pady=10)

# Buttons for actions
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

show_profiles_button = tk.Button(btn_frame, text="Show Wi-Fi Profiles", command=display_wifi_profiles)
show_profiles_button.grid(row=0, column=0, padx=10)

recommend_button = tk.Button(btn_frame, text="Show Recommendations", command=show_recommendations)
recommend_button.grid(row=0, column=1, padx=10)

change_password_button = tk.Button(btn_frame, text="How to Change Wi-Fi Password",
                                   command=show_change_password_instructions)
change_password_button.grid(row=0, column=2, padx=10)

root.mainloop()
