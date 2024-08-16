import tkinter as tk
import tkinter.font as tkFont
import hashlib
import os
import random
import string
import sys
import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from tkinter import messagebox
from tkinter import ttk

# 8/15 - something is weird with decryption_key, add_credentials doesnt work bc of it
# im not even sure if things are being encrypted to the level they need to be 

class PasswordManager:

    # get database , i think this works
    def __init__(self):
        # Get the absolute path to the directory where the executable is located
        if getattr(sys, 'frozen', False):
            # If the application is run as a bundled executable
            base_path = os.path.dirname(sys.executable)
        else:
            # If run as a script
            base_path = os.path.dirname(os.path.abspath(__file__))

        # Define the path to the database file
        self.path_to_database = os.path.join(base_path, "passwords.db")
        self.records_count = 0

        # Check if the database file exists
        if not os.path.exists(self.path_to_database):
            tk.messagebox.showinfo(message="db file doesn't exist. Creating a new one...")
            self.check_db()

        try:
            with open(self.path_to_database, "rb") as db_handle:
                self.db_key_hash = db_handle.read(64).decode()
                self.ciphertext = db_handle.read()
        except Exception as e:
            tk.messagebox.showinfo(message=f"Failed to read the database file: {e}")

    # verify password
    def verify_password(self, password):
        padded_password = self.pad_db_key(password)
        password_hash = hashlib.sha256(padded_password.encode()).hexdigest()
        if (self.db_key_hash == password_hash):
            self.decryption_key = padded_password
            return True
        else:
            return False
        
    def decrypt_db(self):
        if len(self.ciphertext.strip()) != 0:
            aes_encrypt = AES.new(self.decryption_key.encode(), AES.MODE_CBC,
                                self.decryption_key[:16].encode())
            self.content = unpad(aes_encrypt.decrypt(self.ciphertext),
                                AES.block_size).decode("UTF-8")
            self.records_count = len(self.content.split("|"))
        else:
            self.content = ""
            self.records_count  = 0
        
    def save_db(self):
        with open(self.path_to_database, 'wb') as db_handle:
            if self.records_count != 0:
                aes_encrypt = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
                ciphertext = aes_encrypt.encrypt(pad(self.content.encode("UTF-8"), AES.block_size))
            else:
                ciphertext = b""
            db_handle.seek(0)
            db_handle.write(self.db_key_hash.encode() + ciphertext)

    def check_db(self):
        path_to_database = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwords.db")
        try:
            with open(path_to_database, "wb") as db_handle:
                hardcoded_password = "password"
                padded_password = self.pad_db_key(hardcoded_password)
                hardcoded_password_hash = hashlib.sha256(padded_password.encode()).hexdigest()
                db_handle.write(hardcoded_password_hash.encode())
        except Exception as e:
            print(f"Failed to create database file: {e}")
        return path_to_database

    def pad_db_key(self, password):
        if len(password) % 16 == 0:
            return password
        else:
            return password + ("0" * (16 - (len(password) % 16)))

    # this should be fine
    def change_db_pass(self, entry_widget):
        new_password = entry_widget.get()
        new_password = self.pad_db_key(new_password)
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        self.decryption_key = new_password
        self.db_key_hash = new_password_hash
        self.save_db()

    def add_credentials(self, user_entry, pass_entry, platform_entry):
        new_creds = []
        username = user_entry.get()
        password = pass_entry.get()
        platform = platform_entry.get()
        if self.records_count == 0:
                new_creds.extend([str(1), username, password, platform])
                self.content = "-".join(new_creds)
        else:
                record_id = int(self.content.split("|")[-1].split("-")[0]) + 1
                new_creds.extend([str(record_id), username, password, platform])
                self.content = self.content + "|" + "-".join(new_creds)
        self.records_count += 1
        self.save_db()
    
    def del_credentials(self, int):
        if self.records_count != 0:
            record_id_to_delete = None
            try:
                record_id_to_delete = int
            except:
                tk.messagebox.showinfo("no record id found")
            record_index = self.find_record(record_id_to_delete)
            if record_index != None:
                new_records = self.content.split("|")
                del new_records[record_index]
                self.records_count -= 1
                if self.records_count == 0:
                    self.content = ""
                else:
                    self.content = "|".join(new_records)
                self.save_db()

    def find_record(self, record_id):
        records = self.content.split("|")
        records = [record.split("-") for record in records]
        for i in range(len(records)):
            if int(records[i][0]) == record_id:
                return i
        return None

def on_launch():
    manager = PasswordManager()
    initPass = passEntry.get()
    if manager.verify_password(initPass):
        open_next_window(manager)
    else: 
        errorMessage = tk.Label(root, text="invalid password", fg="red", bg="black", font="Courier")
        errorMessage.pack()

def open_next_window(manager):
    root.withdraw()
    mainWindow = tk.Toplevel()
    mainWindow.configure(bg="black")
    mainWindow.geometry("500x210")
    
    # initialize buttons
    showCredBtn = tk.Button(mainWindow, text="show credentials", 
                            fg="antique white", bg="midnight blue", font= "Cascadia 12",
                            command=lambda: show_credentials_window(manager))
    showCredBtn.pack(pady=10)

    addCredBtn = tk.Button(mainWindow, text="add credentials", 
                           fg="antique white", bg="midnight blue", font= "Cascadia 12",
                           command=lambda: add_credentials_window(manager))
    addCredBtn.pack(pady=10)

    delCredBtn = tk.Button(mainWindow, text="delete credentials", 
                           fg="antique white", bg="midnight blue", font= "Cascadia 12",
                           command=lambda: del_credentials_window(manager))
    delCredBtn.pack(pady=10)

    changeMasterPassBtn = tk.Button(mainWindow, text="change password",
                           fg="antique white", bg="midnight blue", font= "Cascadia 12",
                           command=lambda: change_pass_window(manager))
    changeMasterPassBtn.pack(pady=10)

def del_credentials_window(manager):
    delCredWindow = tk.Toplevel()
    delCredWindow.configure(bg="black")
    delCredWindow.geometry("600x230")

    delLabel = tk.Label(delCredWindow, text="what record to delete? (int)", fg="red",
                        bg="black")
    delEntry = tk.Entry(delCredWindow, bg="white", width=10)
    delSubmit = tk.Button(delCredWindow, bg="red", fg="antique white", text="delete record ID",
                          width=15,command=lambda: manager.del_credentials(int(delEntry.get())))

    delLabel.pack(pady=20)
    delEntry.pack(pady=20)
    delSubmit.pack(pady=20)

# create table using treeview
def show_credentials_window(manager):
    showCredWindow = tk.Toplevel()
    showCredWindow.configure(bg="black")
    showCredWindow.geometry("600x400")

    tree = ttk.Treeview(showCredWindow, columns=("record_id", "username", "password", "platform"), 
                           show="headings", height=10)
    tree.heading("record_id", text="ID")
    tree.heading("username", text="username/email")
    tree.heading("password", text="password")
    tree.heading("platform", text="platform")

    tree.column("record_id", width=10, anchor="center")
    tree.column("username", width=150, anchor="center")
    tree.column("password", width=150, anchor="center")
    tree.column("platform", width=150, anchor="center")

    tree.pack(pady=20)

    # decrypt database
    manager.decrypt_db()
    if manager.records_count > 0:
        for record in manager.content.split("|"):
            record_id, username, password, platform = record.split("-")
            tree.insert("", "end", values=(record_id, username, password, platform))
    else:
        tk.messagebox.showinfo("Info", "No credentials stored.")

def add_credentials_window(manager):
    addCredentialsWindow = tk.Toplevel()
    addCredentialsWindow.configure(bg="black")
    addCredentialsWindow.geometry("600x230")
    userLabel = tk.Label(addCredentialsWindow, text="username:", 
                            fg="antique white", bg="black", font="Cascadia 12")
    userLabel.pack(pady=5)
    username = tk.Entry(addCredentialsWindow, width=35)
    username.pack(pady=5)
    passLabel = tk.Label(addCredentialsWindow, text="password:", 
                            fg="antique white", bg="black", font="Cascadia 12")
    passLabel.pack(pady=5)
    password = tk.Entry(addCredentialsWindow, width=35)
    password.pack(pady=5)
    platLabel = tk.Label(addCredentialsWindow, text="platform:", 
                            fg="antique white", bg="black", font="Cascadia 12")
    platLabel.pack(pady=5)
    platform = tk.Entry(addCredentialsWindow, width=35)
    platform.pack(pady=5)

    submitBtn = tk.Button(addCredentialsWindow, text="submit", fg="black", bg="lawn green",
                          font="Cascadia 12", command=lambda: manager.add_credentials(username, password, platform))
    submitBtn.pack(pady=5)

def change_pass_window(manager):
    changePassWindow = tk.Toplevel()
    changePassWindow.configure(bg="black")
    changePassWindow.geometry("500x230")
    changePassLabel = tk.Label(changePassWindow, text="enter new password:"
                               ,fg="antique white", bg="black", font="Cascadia 12")
    changePassLabel.pack(pady=20)
   
    newPassEntry = tk.Entry(changePassWindow, width=35)
    newPassEntry.pack(pady=20)

    savePassBtn = tk.Button(changePassWindow, text="save", font="Courier"
                            ,fg="black", bg="lawn green", command=lambda: manager.change_db_pass(newPassEntry))
    savePassBtn.pack(pady=20)

# configure root
root = tk.Tk()
root.configure(bg="black")
root.geometry("500x250")

# create font styles
dmSans_big = tkFont.Font(family="DM Sans", size=36, weight="bold", slant="italic")
dmSans_small = tkFont.Font(family="DM Sans", size=10, weight="normal")

# when window first opened
label = tk.Label(root, text="bleachPass", font=dmSans_big, fg="antique white", bg="black")
label.pack(pady=10)

passEntry = tk.Entry(root, show="*", width=35, font=dmSans_small)
passEntry.pack(pady=20)

enterButton = tk.Button(root, text="enter", font="Courier", fg="black", bg="lawn green", command=on_launch)
enterButton.pack(pady=20)

tk.mainloop()