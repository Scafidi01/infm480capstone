import tkinter as tk
from tkinter import ttk

window = tk.Tk()
window.geometry('500x400')
window.title('Menu')

menu = tk.Menu(window)

file_menu = tk.Menu(menu, tearoff = False)
file_menu.add_command(label = 'New', command = lambda: print('New file'))
file_menu.add_command(label = "Open", command = lambda: print("Open file"))
file_menu.add_separator()
menu.add_cascade(label = 'File', menu = file_menu)

help_menu = tk.Menu(menu, tearoff= False)
menu.add_cascade(label= "Help entry", compound = lambda: print("Help"))




window.configure(menu = menu)
window.mainloop()