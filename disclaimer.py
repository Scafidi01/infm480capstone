import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.geometry("600x400")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

disclaimer_frame = ttk.Frame(notebook)
notebook.add(disclaimer_frame, text="Disclaimer")

disclaimer_label = tk.Label(
    disclaimer_frame,
    text=(
        "Disclaimer: This tool is for educational purposes only. "
        "Unauthorized use to access or modify networks is illegal. "
        "Use responsibly and ensure you have permission to perform these actions on the target network."
    ),
    wraplength=500,
    justify="left",
    font=("Arial", 12),
    anchor="center",
    bg="white"
)
disclaimer_label.pack(fill="both", expand=True, pady=20, padx=20)

root.mainloop()
