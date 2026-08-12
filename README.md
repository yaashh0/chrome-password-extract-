# Chrome App-Bound Password Decryptor (v20+)

A Python utility designed to decrypt modern Google Chrome saved passwords encrypted using **App-Bound Encryption (v20+)** and standard **v10/v11** formats on Windows systems.

---

## Prerequisites & Requirements

* **Operating System:** Windows 10 / 11 (Administrator privileges are strictly required).
* **Python:** Python 3.8 or higher installed on your system.
* **Google Chrome:** Must be **completely closed** while running the script to avoid database locking errors.

---

## Setup & Installation

Open your command prompt (`cmd`) or PowerShell **as Administrator** and run the following commands sequentially.


```powershell
# Install required dependencies
py -m pip install PythonForWindows cryptography pycryptodome pywin32


# Run the script from your administrator terminal:
password extract decrypt.py
```
<img width="1326" height="800" alt="Screenshot " src="https://github.com/user-attachments/assets/19f1c60d-3c8e-4133-ae6e-7793f9b37259" />
