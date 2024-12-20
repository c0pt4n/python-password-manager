# Password Manager

A secure and user-friendly password manager built with Python, using `customtkinter` for the graphical user interface and SQLite for the database. This application allows you to generate strong passwords, securely store them, and manage them through an encrypted vault.

## Features

- **Password Generator**: Create strong and customizable passwords with a mix of letters, digits, and symbols.
- **Secure Vault**: Store account credentials securely using AES encryption.
- **Master Password**: Protect your vault with a master password and recovery key.
- **Recovery Key**: Reset your master password using a unique recovery key.
- **Password Management**: Add, update, delete, and view your stored credentials.
- **Dark Mode**: A visually appealing dark-themed UI.

## Prerequisites

Before running the application, ensure you have the following installed:

- Python3
- Required Python libraries:
  ```bash
  pip install cryptography pyperclip customtkinter pillow
  ```

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/BolaWagdy/python-password-manager.git
   cd python-password-manager
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python password-vault.py
   ```

## Usage

### Initial Setup
- On first launch, you'll be prompted to create a **master password**. Save the recovery key securely as it is required to reset the master password.

### Password Generator
- Set the desired number of letters, digits, and symbols using sliders.
- Click **Generate Password** to create a strong password.
- Copy the generated password to the clipboard using the **Copy Password** button.

### Password Vault
- Unlock the vault by entering your **master password**.
- Manage your credentials:
  - Add new entries (Account, Username, Password).
  - Copy usernames or passwords directly to the clipboard.
  - Update or delete existing entries.

### Reset Master Password
- If you forget your master password, click **Forgot Password?** and enter your recovery key to reset it.

## File Structure

```
└── 📁images
    └── lock.png
└── old.py
└── password-vault.py
└── PROJECT-REPORT.docx
└── README.md
└── requirements.txt
```

## Security

- Passwords are encrypted using **AES encryption** from the `cryptography` library.
- The master password and recovery key are hashed using **SHA-256** for secure storage.

<!-- ## Screenshots

| **Password Generator** | **Vault** |
|-------------------------|-----------|
| ![Password Generator](https://via.placeholder.com/400x300?text=Password+Generator) | ![Vault](https://via.placeholder.com/400x300?text=Vault+UI) |
 -->
