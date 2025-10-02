# Password Vault

This project is a **password manager** developed to securely store account information.
Users can securely store, view, and manage their usernames and passwords for other services by setting a **Master Password**.

## Features
- Login with **Master Password**
- Strong **encryption** with AES-256-GCM
- Add,list,delete an account
- Generate strong passwords automatically
- Copy passwords (Clipboard support)
- Change master password
- GUI (PyQt6) interface support
- Database: **SQLite**



## Technologies Used
- [Python 3.10+](https://www.python.org/)
- [PyQt6](https://pypi.org/project/PyQt6/) → GUI
- [pycryptodome](https://pypi.org/project/pycryptodome/) → AES 
- [SQLite3](https://www.sqlite.org/index.html) → Database

## Setup
First, install the dependencies:
```bash
pip install pyqt6 pycryptodome pwinput
```

To run the project:
```bash
python main.py
```

## Usage
1. Upon first launch, you will be prompted to create a **Master Password**.
2. You can then log in with this password to add your accounts.
3. When you enter the service and username via “Add Account,” a strong password is automatically generated and stored in the database in an encrypted format.
4. You can view all your accounts via “List Accounts.”
5. You can copy the password to the clipboard using “Copy Selected Password”.
6. You can update your current password using “Change Master Password”.

## Security
- Passwords are encrypted using the AES-256-GCM algorithm.
- The master password is stored using **salt + PBKDF2**.
- Unique strong passwords can be generated for each account.

## 📜 Licence
This project is licensed under MIT.

## Notes
This project only supports the Turkish language.
If you want to use the application, you can convert it to an exe file and use it.
