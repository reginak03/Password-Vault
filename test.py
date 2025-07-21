import tkinter as tk
from tkinter import font

root = tk.Tk()
print(font.families())
root.destroy()

# import sqlite3

# conn = sqlite3.connect("vault.db")
# cursor = conn.cursor()

# cursor.execute("PRAGMA table_info(vault);")
# columns = cursor.fetchall()

# for col in columns:
#     print(col)

# conn.close()