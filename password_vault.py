from tkinter import *
from tkinter import messagebox, simpledialog, Entry, Button, ttk, filedialog
from PIL import ImageTk, Image

from cryptography.fernet import Fernet #for AES encryption/decryption
import sqlite3

#for password generation:
import secrets
import string

from master_password import (
    is_master_password_set,
    save_master_password,
    check_master_password,
    derive_key
)

class PasswordVault:
    def __init__(self, root):
        self.window = root
        self.window.geometry("720x400")
        self.window.title("Password Vault")
        self.window.resizable(width = False, height = False)
        self.window.configure(bg="gray90")

        if not is_master_password_set():
            vault_key = simpledialog.askstring("Set Master Password", "Create Your Master Password:", show="*")
            if not vault_key:
                messagebox.showerror("Error", "Vault Cannot Work Without a Master Password.")
                self.window.destroy()
                return
            save_master_password(vault_key)
            messagebox.showinfo("Master Password Set", "Master Password Saved. Don't Forget It!")
        
        else:
            #master password already exists, ask user to unlock
            vault_key = simpledialog.askstring("Unlock Vault", "Enter Your Master Password:", show="*")
            if not vault_key or not check_master_password(vault_key):
                messagebox.showerror("Access Denied", "Incorrect Vault Key!")
                self.window.destroy()
                return
        
        self.fernet = Fernet(derive_key(vault_key))

        #GUI components:
        #frame 1: logo & exit button
        self.frame_1 = Frame(self.window,bg="gray90", width=100, height=100)
        self.frame_1.place(x=20, y=20)
        self.display_logo()
        #exit button to close the application
        Exit_Btn = Button(self.window, text="Exit", font=("Arial", 10, "bold"), fg="red", width=5, command=self.exit_window)
        Exit_Btn.place(x=640, y=20)

        #frame 2: main page widgets
        self.frame_2 = Frame(self.window, bg="white", width=720, height=480)
        self.frame_2.place(x=0, y=110)
        self.main_window()
        #to track the opened windows:
        self.add_window = None
        self.generate_window = None
        self.edit_window = None
        self.delete_window = None 
        self.vault_window = None
        
    #application logo and title
    def display_logo(self):
        image = Image.open("Images/vault-logo.png")
        resized_image = image.resize((150, 80))
        self.logo = ImageTk.PhotoImage(resized_image)
        label = Label(self.frame_1, bg="gray90",image=self.logo)
        label.pack(side=LEFT, padx=5)
        title_label = Label(self.frame_1, text="Password Vault", font=("Times New Roman", 28, "bold"), bg="gray90", fg="black")
        title_label.pack(side=LEFT, padx=10)

    def main_window(self):
        Heading_Label = Label(self.frame_2, text="Welcome To Your Secure Password Manager", font=("Times", 22, "bold"), bg="white", fg="black")
        Heading_Label.place(x=100, y=20)
        Add_Button = Button(self.frame_2, text="Add New Credentials", font=("Times", 10, "bold"), bg="white", fg="black", width=14, command=self.add_entry)
        Add_Button.place(x=180, y=80)

        Generate_Button = Button(self.frame_2, text="Password Generator", font=("Times", 10, "bold"), bg="white", fg="black", width=14, command=self.generate_password)
        Generate_Button.place(x=330, y=80)

        View_Button = Button(self.frame_2, text="Open Vault", font=("Times", 20, "bold"), bg="white", fg="brown", command=self.get_entries)
        View_Button.place(x=250, y=140)
        vault_text = Label(self.frame_2, text="Open the Vault to view, edit and delete your credentials", font=("Times", 10, "bold"), bg="white", fg="black")
        vault_text.place(x=180, y=180)

    #function to store a new user entry (add credentials)
    def add_entry(self):
        if self.add_window is not None and self.add_window.winfo_exists():
            self.add_window.destroy()

        self.add_window = Toplevel(self.window)
        self.add_window.title("Add New Credentials")
        self.add_window.geometry("700x300")
        Label(self.add_window, text="Please Enter the Credentials You'd Like to Add to Your Vault", font=("Helvetica", 14, "bold")).pack(pady=25)

        site = Label(self.add_window, text="Site:", font=("Helvetica", 14), fg="white")
        site.place(x=250, y=80)
        self.site_entry = Entry(self.add_window, font=("Helvetica", 12), width=22, bg="white", fg="black", insertbackground="black") 
        self.site_entry.place(x=290, y=80)

        username = Label(self.add_window, text="Username:", font=("Helvetica", 14), fg="white")
        username.place(x=210, y=120)
        self.username_entry = Entry(self.add_window, font=("Helvetica", 12), width=22, bg="white", fg="black", insertbackground="black") 
        self.username_entry.place(x=290, y=120)

        password = Label(self.add_window, text="Password:", font=("Helvetica", 14), fg="white")
        password.place(x=210, y=160)
        self.password_entry = Entry(self.add_window, font=("Helvetica", 12), width=22, bg="white", fg="black", insertbackground="black") 
        self.password_entry.place(x=290, y=160)

        notes = Label(self.add_window, text="Notes (optional):", font=("Helvetica", 14), fg="white")
        notes.place(x=175, y=200)
        self.notes_entry = Entry(self.add_window, font=("Helvetica", 12), width=22, bg="white", fg="black", insertbackground="black") 
        self.notes_entry.place(x=290, y=200)

        submit_button = Button(self.add_window, text="Add to Vault", font=("Helvetica", 14, "bold"), fg="green", command=self.validate_entry)
        submit_button.place(x=220, y=245)
        reset_button = Button(self.add_window, text="Reset", font=("Helvetica", 14, "bold"), fg="red", command=self.reset)
        reset_button.place(x=340, y=245)

    def validate_entry(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        notes = self.notes_entry.get()  

        if not site or not username or not password:
            messagebox.showerror("Missing Fields", "Site, Username, and Password are required fields.")
            return
        
        try:
            print(self.fernet)
            encrypted_password = self.fernet.encrypt(password.encode()) #encrypt password before storing
            self.store_entry(site, username, encrypted_password, notes)
            messagebox.showinfo("Success", "Credentials Added to Your Vault!")
            #self.reset()
            self.add_window.destroy()

        except Exception as e:
            print("Error Storing Credentials:", e)
            messagebox.showerror("Error", f"An Error Occurred While Saving: {str(e)}")


    def store_entry(self, site, username, password, notes):
        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO vault (site, username, password, notes) VALUES (?, ?, ?, ?)", (site, username, password, notes))
        conn.commit()
        conn.close()
        self.reset()

    def generate_password(self, length=16):
        if self.generate_window is not None and self.generate_window.winfo_exists():
            self.generate_window.destroy()

        self.generate_window = Toplevel(self.window)
        self.generate_window.title("Password Generator")
        self.generate_window.geometry("600x300")
        self.generate_window.resizable(False, False)

        Label(self.generate_window, text="Customize Your Password:", font=("Helvetica", 14, "bold")).pack(pady=10)

        #password options
        include_upper = BooleanVar(value=True)
        include_lower = BooleanVar(value=True)
        include_digits = BooleanVar(value=True)
        include_symbols = BooleanVar(value=True)
        password_length = IntVar(value=16)

        options_frame = Frame(self.generate_window)
        options_frame.pack(pady=5)

        Checkbutton(options_frame, text="Include Uppercase Letters", variable=include_upper).grid(row=0, column=0, sticky="w")
        Checkbutton(options_frame, text="Include Lowercase Letters", variable=include_lower).grid(row=1, column=0, sticky="w")
        Checkbutton(options_frame, text="Include Numbers", variable=include_digits).grid(row=0, column=1, sticky="w", padx=20)
        Checkbutton(options_frame, text="Include Symbols", variable=include_symbols).grid(row=1, column=1, sticky="w", padx=20)

        #password length selection
        Label(self.generate_window, text="Password Length:").pack()
        Spinbox(self.generate_window, from_=8, to=64, textvariable=password_length, width=5).pack()

        #generated password display
        self.generated_password_entry = Entry(self.generate_window, font=("Helvetica", 14), width=30, justify='center')
        self.generated_password_entry.pack(pady=10)

        def build_charset():
            charset = ""
            if include_upper.get():
                charset += string.ascii_uppercase
            if include_lower.get():
                charset += string.ascii_lowercase
            if include_digits.get():
                charset += string.digits
            if include_symbols.get():
                charset += string.punctuation
            return charset

        def create_password():
            charset = build_charset()
            if not charset:
                messagebox.showerror("Invalid Selection", "Please Select At Least One Character Type.")
                return
            length = password_length.get()
            password = ''.join(secrets.choice(charset) for _ in range(length))
            self.generated_password_entry.config(state='normal')
            self.generated_password_entry.delete(0, END)
            self.generated_password_entry.insert(0, password)
            self.generated_password_entry.config(state='readonly')

        def copy_to_clipboard():
            password = self.generated_password_entry.get()
            self.window.clipboard_clear()
            self.window.clipboard_append(password)
            messagebox.showinfo("Copied", "Password Copied to Clipboard!")

        Button(self.generate_window, text="Generate", font=("Helvetica", 12, "bold"), command=create_password).pack(pady=5)
        Button(self.generate_window, text="Copy to Clipboard", font=("Helvetica", 12), command=copy_to_clipboard).pack(pady=5)

        #to auto-generate first password
        create_password()
            
    #function to retrieve and decrypt user entries
    def get_entries(self):
        if self.vault_window is not None and self.vault_window.winfo_exists():
            self.vault_window.destroy()

        self.vault_window = Toplevel(self.window)
        self.vault_window.title("Credentials Retrieval")
        self.vault_window.geometry("760x400")

        #master key entry:
        Label(self.vault_window, text="Vault Key:", font=("Helvetica", 12)).place(x=20, y=10)
        self.vault_key_entry = Entry(self.vault_window, font=("Helvetica", 12), width=22, show="*")
        self.vault_key_entry.place(x=80, y=8)

        proceed_button = Button(self.vault_window, text="Proceed", font=("Helvetica", 12, "bold"), fg='green', command=self.unlock_vault)
        proceed_button.place(x=250, y=7)

        #table for displaying credentials
        columns = ("Site", "Username", "Password (Encrypted)", "Notes")
        self.tree = ttk.Treeview(self.vault_window, columns=columns, show="headings", height=15)
        for col in columns:
            #Treeview table to list entries cleanly
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180, anchor="center")
        self.tree.place(x=20, y=50)

        conn = sqlite3.connect("vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT site, username, password, notes FROM vault")
        self.rows = cursor.fetchall()
        conn.close()

        #first load encrypted data
        for row in self.rows:
            site, username, enc_pass, notes = row
            self.tree.insert("", "end", values=(site, username, enc_pass, notes))

    def unlock_vault(self):
        vault_key = self.vault_key_entry.get()

        #validate the master password (compare hash)
        if not check_master_password(vault_key):
            messagebox.showerror("Access Denied", "Incorrect Vault Key!")
            return

        self.fernet = Fernet(derive_key(vault_key))
        
        #if correct, decrypt passwords and update the table
        self.tree.delete(*self.tree.get_children())  #clear table first
        self.tree.heading("Password (Encrypted)", text="Password (Decrypted)")

        for row in self.rows:
            site, username, enc_pass, notes = row
            try:
                decrypted_password = self.fernet.decrypt(enc_pass).decode()
            except Exception as e:
                #print(f"Decryption error: {e}")  #debugging
                decrypted_password = "[Decryption Failed]"

            self.tree.insert("", "end", values=(site, username, decrypted_password, notes))

        export_button = Button(self.vault_window, text="Export", font=("Helvetica", 12, "bold"), width=12, command=self.export_entries)
        export_button.place(x=350, y=7)

        edit_button = Button(self.vault_window, text="Edit Entry", font=("Helvetica", 12, "bold"), width=12, command=self.edit_entry)
        edit_button.place(x=620, y=2)

        delete_button = Button(self.vault_window, text="Delete Entry", font=("Helvetica", 12, "bold"), width=12, fg="red", command=self.delete_entry)
        delete_button.place(x=620, y=25)

        messagebox.showinfo("Vault Unlocked", "You Now Have Full Access to your Credentials!")

    def export_entries(self):
        try:
            # conn = sqlite3.connect("vault.db")
            # cursor = conn.cursor()
            # cursor.execute("SELECT site, username, password, notes FROM vault")
            # rows = cursor.fetchall()
            # conn.close()

            if not self.rows:
                messagebox.showinfo("No Data", "There are no entries to export.")
                return

            #prepare the content
            export_data = ""
            for row in self.rows:
                site, username, password, notes = row
                #decrypt password before exporting
                try:
                    decrypted_password = self.fernet.decrypt(password).decode()
                except Exception as e:
                    decrypted_password = "<Decryption Failed>"
                export_data += f"Site: {site}\nUsername: {username}\nPassword: {decrypted_password}\nNotes: {notes}\n\n"

            #encrypt the entire content
            encrypted_data = self.fernet.encrypt(export_data.encode())

            #ask user where to save
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt")],
                title="Export Vault Entries"
            )

            if file_path:
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Export Successful", "Vault entries have been encrypted and exported successfully.")
        except Exception as e:
            print("Export Error:", e)
            messagebox.showerror("Error", f"Failed to export entries:\n{str(e)}")
    #to import and decrypt the .txt file later, read the file in binary mode and use self.fernet.decrypt(...) to recover the text

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No entry selected.")
            return

        item = self.tree.item(selected[0])
        site, username, password, notes = item['values']

        #new window for editing
        self.edit_window = Toplevel(self.window)
        self.edit_window.title("Edit Entry")
        self.edit_window.geometry("400x300")

        Label(self.edit_window, text="Edit the Credentials Below", font=("Helvetica", 14)).pack(pady=10)

        Label(self.edit_window, text="Site").pack()
        site_entry = Entry(self.edit_window)
        site_entry.pack()
        site_entry.insert(0, site)

        Label(self.edit_window, text="Username").pack()
        username_entry = Entry(self.edit_window)
        username_entry.pack()
        username_entry.insert(0, username)

        Label(self.edit_window, text="Password").pack()
        password_entry = Entry(self.edit_window)
        password_entry.pack()
        password_entry.insert(0, password)

        Label(self.edit_window, text="Notes").pack()
        notes_entry = Entry(self.edit_window)
        notes_entry.pack()
        notes_entry.insert(0, notes)

        def save_changes():
            new_site = site_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            new_notes = notes_entry.get()

            if not new_site or not new_username or not new_password:
                messagebox.showerror("Error", "Site, Username, and Password are required.")
                return

            encrypted_password = self.fernet.encrypt(new_password.encode())

            conn = sqlite3.connect("vault.db")
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE vault 
                SET site=?, username=?, password=?, notes=?
                WHERE site=? AND username=?
            """, (new_site, new_username, encrypted_password, new_notes, site, username))
            conn.commit()
            conn.close()

            # Update the Treeview entry directly
            decrypted_password = new_password  # already known from user input
            self.tree.item(selected[0], values=(new_site, new_username, decrypted_password, new_notes)) #selected[0]=row ID, self.tree.item updates that specific row

            self.edit_window.destroy()
            messagebox.showinfo("Updated", "Entry updated successfully.")

        Button(self.edit_window, text="Save Changes", command=save_changes).pack(pady=10)

    def delete_entry(self): 
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No entry selected.")
            return

        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?")
        if confirm:
            item = self.tree.item(selected[0])
            site = item['values'][0]
            username = item['values'][1]

            conn = sqlite3.connect("vault.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vault WHERE site=? AND username=?", (site, username))
            conn.commit()
            conn.close()

            self.tree.delete(selected[0])
            messagebox.showinfo("Deleted", "Entry deleted successfully.")


    def reset(self):
        self.site_entry.delete(0, END)
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
        self.notes_entry.delete(0, END)
            
    #function for the "Exit" button in the application header
    def exit_window(self):
        self.window.destroy()

#create an instance of the PasswordVault class to build the GUI, then start the main loop
if __name__ == "__main__": #check if the script is being run as the main program (to ensure that the code inside this block only runs when the script is executed, not when imported as a module...)
    root = Tk()
    obj = PasswordVault(root)
    root.mainloop()

############################################
    #old generate_password (without options)
    # def generate_password(self, length=16):
    #     if self.generate_window is not None and self.generate_window.winfo_exists():
    #         self.generate_window.destroy()

    #     self.generate_window = Toplevel(self.window)
    #     self.generate_window.title("Password Generator")
    #     self.generate_window.geometry("600x200")
    #     Label(self.generate_window, text="This is a Randomly Generated Password, Copy & Use It As You Wish:)", font=("Helvetica", 14, "bold")).pack(pady=25)

    #     alphabet = string.ascii_letters + string.digits + string.punctuation
    #     password = ''.join(secrets.choice(alphabet) for _ in range(length))

    #     #show the generated password in a readonly entry (so it can be selected/copied)
    #     self.generated_password_entry = Entry(self.generate_window, font=("Helvetica", 14), width=30, justify='center')
    #     self.generated_password_entry.insert(0, password)
    #     self.generated_password_entry.config(state='readonly')  #make it read-only
    #     self.generated_password_entry.pack(pady=10)

    #     def copy_to_clipboard():
    #         self.window.clipboard_clear()
    #         self.window.clipboard_append(password)
    #         messagebox.showinfo("Copied", "Password Copied to Clipboard!")
        
    #     copy_button = Button(self.generate_window, text="Copy to Clipboard", font=("Helvetica", 14), command=copy_to_clipboard)
    #     copy_button.pack(pady=10)