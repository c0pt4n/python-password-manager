import os
import random
import sqlite3
import hashlib
import uuid
import pyperclip
import base64
from tkinter import simpledialog, messagebox
from customtkinter import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from tkinter import ttk
from tkinter import Menu
from PIL import Image

# Set up the appearance of CustomTkinter
set_appearance_mode("dark")
set_default_color_theme("blue")

# Encryption setup
backend = default_backend()
salt = b"2444"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend
)

# Global variable for encryption key
encryptionkey = Fernet.generate_key()

class PasswordManagerApp(CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Generator & Vault")
        self.geometry(
            f"400x550+{(self.winfo_screenwidth() // 2) - 200}+{(self.winfo_screenheight() // 2) - 275}"
        )
        self.resizable(False, False)

        # Initialize database
        self.db = sqlite3.connect("password-vault.db")
        self.cursor = self.db.cursor()
        self.setup_database()

        # UI Variables
        self.no_of_letters = IntVar(value=3)
        self.no_of_digits = IntVar(value=3)
        self.no_of_symbols = IntVar(value=3)
        self.generated_password = StringVar()

        # GUI Layout
        self.create_main_ui()

    def setup_database(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS masterpassword(
                id INTEGER PRIMARY KEY,
                password TEXT NOT NULL,
                recoverykey TEXT NOT NULL
            )
        """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault(
                id INTEGER PRIMARY KEY,
                ACCOUNT TEXT NOT NULL,
                USERNAME TEXT NOT NULL,
                PASSWORD TEXT NOT NULL
            )
        """
        )
        self.db.commit()

    def create_main_ui(self):
        # Heading
        current_dir = os.getcwd()
        image_path = os.path.join(current_dir, "images", "lock.png")
        image = Image.open(image_path)
        image_resized = image.resize((27, 27))

        img = CTkImage(light_image=image_resized, size=(27, 27))
        # Create the label with the image beside the text
        label = CTkLabel(
            self,
            text="Password Generator",
            font=("Arial", 26),
            image=img,
            compound="right",
        )
        label.pack(pady=15)

        # Letter selection
        CTkLabel(self, text="Number of Letters:").pack()
        self.letter_slider_value = CTkLabel(self, text=f"{self.no_of_letters.get()}")
        self.letter_slider_value.pack()
        CTkSlider(
            self,
            from_=3,
            to=10,
            variable=self.no_of_letters,
            command=lambda v: self.update_slider_value(self.letter_slider_value, v),
        ).pack(pady=5)

        # Digit selection
        CTkLabel(self, text="Number of Digits:").pack()
        self.digit_slider_value = CTkLabel(self, text=f"{self.no_of_digits.get()}")
        self.digit_slider_value.pack()
        CTkSlider(
            self,
            from_=3,
            to=10,
            variable=self.no_of_digits,
            command=lambda v: self.update_slider_value(self.digit_slider_value, v),
        ).pack(pady=5)

        # Symbol selection
        CTkLabel(self, text="Number of Symbols:").pack()
        self.symbol_slider_value = CTkLabel(self, text=f"{self.no_of_symbols.get()}")
        self.symbol_slider_value.pack()
        CTkSlider(
            self,
            from_=3,
            to=10,
            variable=self.no_of_symbols,
            command=lambda v: self.update_slider_value(self.symbol_slider_value, v),
        ).pack(pady=5)

        # Generate Password Button
        self.generate_btn = CTkButton(
            self,
            text="Generate Password",
            command=self.generate_password,
            fg_color="#008000",  # Set the button's background color
            hover_color="#355E3B",
        )  # Set the hover color
        self.generate_btn.pack(pady=10)

        # Display Password
        self.password_display = CTkEntry(
            self, textvariable=self.generated_password, state="readonly"
        )
        self.password_display.pack(pady=10)

        # Copy Button
        self.copy_btn = CTkButton(
            self, text="Copy Password", command=self.copy_password
        )
        self.copy_btn.pack(pady=10)

        # Open Vault Button
        self.vault_btn = CTkButton(self, text="Open Vault", command=self.open_vault)
        self.vault_btn.pack(pady=10)

    def update_slider_value(self, label, value):
        """Update the label text with the current slider value."""
        label.configure(text=f"{int(float(value))}")

    def generate_password(self):
        letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        symbols = "#$%&()*+-./:;<=>?@[\\]^_{|}"

        password = random.choices(letters, k=self.no_of_letters.get())
        password += random.choices(digits, k=self.no_of_digits.get())
        password += random.choices(symbols, k=self.no_of_symbols.get())

        random.shuffle(password)
        self.generated_password.set("".join(password))

    def copy_password(self):
        pyperclip.copy(self.generated_password.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def hash_password(self, input_password):
        return hashlib.sha256(input_password.encode()).hexdigest()

    def initialize_master_password(self):
        """Prompt the user to set up a master password and recovery key."""

        def save_master_password():
            master_password = password_entry.get()
            confirm_password = confirm_entry.get()

            if master_password == confirm_password:
                hashed_password = self.hash_password(master_password)

                # Generate recovery key
                recovery_key = str(uuid.uuid4().hex)
                hashed_recovery_key = self.hash_password(recovery_key)

                # Save to database
                self.cursor.execute("DELETE FROM masterpassword WHERE id=1")
                self.cursor.execute(
                    "INSERT INTO masterpassword (id, password, recoverykey) VALUES (?, ?, ?)",
                    (1, hashed_password, hashed_recovery_key),
                )
                self.db.commit()

                # Show recovery key to the user
                display_recovery_key(recovery_key)
                setup_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match!")
                password_entry.delete(0, "end")
                confirm_entry.delete(0, "end")

        def display_recovery_key(recovery_key):
            """Display the recovery key with a copy button."""
            recovery_window = CTkToplevel(self)
            recovery_window.title("Recovery Key")
            recovery_window.geometry("400x250")
            recovery_window.resizable(False, False)

            CTkLabel(
                recovery_window, text="Your Recovery Key:", font=("Arial", 14)
            ).pack(pady=10)

            # Recovery key entry (readonly)
            key_entry = CTkEntry(recovery_window, width=300)
            key_entry.insert(0, recovery_key)
            key_entry.configure(state="readonly")  # Prevent editing
            key_entry.pack(pady=5)

            # Copy button
            def copy_to_clipboard():
                self.clipboard_clear()
                self.clipboard_append(recovery_key)
                self.update()  # Update clipboard
                messagebox.showinfo("Copied", "Recovery key copied to clipboard!")

            copy_button = CTkButton(
                recovery_window, text="Copy", command=copy_to_clipboard
            )
            copy_button.pack(pady=10)

            def finish_and_login():
                recovery_window.destroy()
                VaultWindow(self.db, self.cursor).mainloop()  # Open the vault window

            done_button = CTkButton(
                recovery_window, text="Done", command=finish_and_login
            )
            done_button.pack(pady=10)

            CTkLabel(
                recovery_window,
                text="Save this key securely!",
                wraplength=400,
                font=("Arial", 12),
                text_color="green",
            ).pack(pady=5)

        # Create setup window
        setup_window = CTkToplevel(self)
        setup_window.title("Set Master Password")
        setup_window.geometry("350x250")
        setup_window.resizable(False, False)

        CTkLabel(setup_window, text="Create Master Password", font=("Arial", 14)).pack(
            pady=10
        )

        password_entry = CTkEntry(setup_window, show="*", width=200)
        password_entry.pack(pady=5)
        password_entry.focus()

        CTkLabel(setup_window, text="Confirm Master Password").pack(pady=5)

        confirm_entry = CTkEntry(setup_window, show="*", width=200)
        confirm_entry.pack(pady=5)

        save_btn = CTkButton(setup_window, text="Save", command=save_master_password)
        save_btn.pack(pady=10)

    def reset_master_password(self):
        """Allow the user to reset the master password using the recovery key."""

        def check_recovery_key():
            entered_key = recovery_key_entry.get()
            hashed_key = self.hash_password(entered_key)

            # Verify recovery key
            self.cursor.execute(
                "SELECT * FROM masterpassword WHERE recoverykey=?", (hashed_key,)
            )
            result = self.cursor.fetchone()

            if result:
                reset_window.destroy()
                self.initialize_master_password()
            else:
                messagebox.showerror("Error", "Invalid recovery key!")
                recovery_key_entry.delete(0, "end")

        # Create reset window
        reset_window = CTkToplevel(self)
        reset_window.title("Reset Master Password")
        reset_window.geometry("350x150")
        reset_window.resizable(False, False)

        CTkLabel(reset_window, text="Enter Recovery Key", font=("Arial", 14)).pack(
            pady=10
        )

        recovery_key_entry = CTkEntry(reset_window, width=200)
        recovery_key_entry.pack(pady=5)
        recovery_key_entry.focus()

        reset_btn = CTkButton(
            reset_window, text="Reset Password", command=check_recovery_key
        )
        reset_btn.pack(pady=10)

    def open_vault(self):
        """Open the vault after verifying the master password."""

        def check_master_password():
            entered_password = password_entry.get()
            hashed_password = self.hash_password(entered_password)

            # Verify master password from the database
            self.cursor.execute(
                "SELECT * FROM masterpassword WHERE id=1 AND password=?",
                (hashed_password,),
            )
            result = self.cursor.fetchone()

            if result:
                vault_window.destroy()
                VaultWindow(self.db, self.cursor).mainloop()
            else:
                messagebox.showerror("Error", "Incorrect Master Password!")
                password_entry.delete(0, "end")

        # Check if master password is set
        self.cursor.execute("SELECT * FROM masterpassword WHERE id=1")
        if not self.cursor.fetchone():
            self.initialize_master_password()
            return

        # Create password entry window
        vault_window = CTkToplevel(self)
        vault_window.title("Unlock Vault")
        vault_window.geometry("300x200")
        vault_window.resizable(False, False)

        CTkLabel(vault_window, text="Enter Master Password", font=("Arial", 14)).pack(
            pady=10
        )

        password_entry = CTkEntry(vault_window, show="*", width=200)
        password_entry.pack(pady=10)
        password_entry.focus()

        unlock_btn = CTkButton(
            vault_window, text="Unlock", command=check_master_password
        )
        unlock_btn.pack(pady=10)

        def reset_master_password_with_close():
            vault_window.destroy()  # Close the current unlock window
            self.reset_master_password()  # Open the recovery key window

        reset_btn = CTkButton(
            vault_window,
            text="Forgot Password?",
            command=reset_master_password_with_close,
        )
        reset_btn.pack(pady=5)

class VaultWindow(CTkToplevel):
    def __init__(self, db, cursor):
        super().__init__()
        self.db = db
        self.cursor = cursor
        self.geometry("700x600")
        self.title("Password Vault")
        self.resizable(False, False)

        # Vault Screen UI
        self.create_vault_ui()

    def create_vault_ui(self):
        CTkLabel(self, text="Password Vault", font=("Arial", 28)).pack(pady=20)

        # Add Entry Button
        add_btn = CTkButton(
            self,
            text="Add Entry",
            command=self.add_entry,
            fg_color="#008000",  # Set background color (green)
            hover_color="#355E3B",  # Set hover background color (dark green)
            text_color="white",
        )  # Set text color (white)
        add_btn.pack(pady=10)

        # Vault Table
        self.vault_table = ttk.Treeview(
            self, columns=("Account", "Username", "Password"), show="headings"
        )
        self.vault_table.heading("Account", text="Account")
        self.vault_table.heading("Username", text="Username")
        self.vault_table.heading("Password", text="Password")
        self.vault_table.column("Account", width=200, anchor="center")
        self.vault_table.column("Username", width=200, anchor="center")
        self.vault_table.column("Password", width=200, anchor="center")
        self.vault_table.pack(pady=10, fill="both", expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.vault_table.yview
        )
        self.vault_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Context Menu for Actions
        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Update Entry", command=self.update_entry)
        self.context_menu.add_command(label="Delete Entry", command=self.delete_entry)

        self.vault_table.bind("<Button-3>", self.show_context_menu)  # Right-click menu

        # Load Entries
        self.load_entries()

    def load_entries(self):
        for row in self.vault_table.get_children():
            self.vault_table.delete(row)

        self.cursor.execute("SELECT id, ACCOUNT, USERNAME, PASSWORD FROM vault")
        entries = self.cursor.fetchall()
        if entries:
            for entry in entries:
                decrypted_password = Fernet(encryptionkey).decrypt(entry[3]).decode()
                masked_password = "*" * len(
                    decrypted_password
                )  # Replace password with asterisks
                self.vault_table.insert(
                    "",
                    "end",
                    values=(entry[1], entry[2], masked_password),
                    iid=entry[0],
                )
        else:
            self.vault_table.insert("", "end", values=("", "No entries found", ""))

    def add_entry(self):
        account = simpledialog.askstring("Input", "Enter Account Name:")
        username = simpledialog.askstring("Input", "Enter Username:")
        password = simpledialog.askstring("Input", "Enter Password:")

        if account and username and password:
            # Encrypt Password
            encrypted_password = Fernet(encryptionkey).encrypt(password.encode())
            self.cursor.execute(
                "INSERT INTO vault (ACCOUNT, USERNAME, PASSWORD) VALUES (?, ?, ?)",
                (account, username, encrypted_password),
            )
            self.db.commit()
            messagebox.showinfo("Success", "Entry Added Successfully!")
            self.load_entries()
        else:
            messagebox.showwarning("Warning", "All fields are required!")

    def copy_username(self):
        selected_item = self.vault_table.focus()
        if selected_item:
            username = self.vault_table.item(selected_item, "values")[1]
            pyperclip.copy(username)
            messagebox.showinfo("Copied", "Username copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No entry selected!")

    def copy_password(self):
        selected_item = self.vault_table.focus()
        if selected_item:
            password = self.vault_table.item(selected_item, "values")[2]
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No entry selected!")

    def update_entry(self):
        selected_item = self.vault_table.focus()
        if selected_item:
            current_account = self.vault_table.item(selected_item, "values")[0]
            current_username = self.vault_table.item(selected_item, "values")[1]
            current_password = self.vault_table.item(selected_item, "values")[2]

            # Get updated values
            new_account = simpledialog.askstring(
                "Input", "Update Account Name:", initialvalue=current_account
            )
            new_username = simpledialog.askstring(
                "Input", "Update Username:", initialvalue=current_username
            )
            new_password = simpledialog.askstring(
                "Input", "Update Password:", initialvalue=current_password
            )

            if new_account and new_username and new_password:
                encrypted_password = Fernet(encryptionkey).encrypt(
                    new_password.encode()
                )
                self.cursor.execute(
                    "UPDATE vault SET ACCOUNT = ?, USERNAME = ?, PASSWORD = ? WHERE id = ?",
                    (new_account, new_username, encrypted_password, selected_item),
                )
                self.db.commit()
                messagebox.showinfo("Success", "Entry Updated Successfully!")
                self.load_entries()
            else:
                messagebox.showwarning("Warning", "All fields are required!")
        else:
            messagebox.showwarning("Warning", "No entry selected!")

    def delete_entry(self):
        selected_item = self.vault_table.focus()
        if selected_item:
            confirm = messagebox.askyesno(
                "Confirm", "Are you sure you want to delete this entry?"
            )
            if confirm:
                self.cursor.execute("DELETE FROM vault WHERE id = ?", (selected_item,))
                self.db.commit()
                messagebox.showinfo("Success", "Entry Deleted Successfully!")
                self.load_entries()
        else:
            messagebox.showwarning("Warning", "No entry selected!")

    def show_context_menu(self, event):
        try:
            # Select row under cursor
            row_id = self.vault_table.identify_row(event.y)
            self.vault_table.selection_set(row_id)
            self.context_menu.post(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

if __name__ == "__main__":
    # Set encryption key globally
    encryptionkey = base64.urlsafe_b64encode(kdf.derive(b"secret_password"))
    app = PasswordManagerApp()
    app.mainloop()