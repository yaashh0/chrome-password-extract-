# Chrome App-Bound Password Decryptor (v20+)

A Python utility designed to decrypt modern Google Chrome saved passwords encrypted using **App-Bound Encryption (v20+)** and standard **v10/v11** formats on Windows systems.

---

## Prerequisites & Requirements

* **Operating System:** Windows 10 / 11 (Administrator privileges are strictly required).
* **Python:** Python 3.8 or higher installed on your system.
* **Google Chrome:** Must be **completely closed** while running the script to avoid database locking errors.

---

## Setup & Installation

Open your command prompt (`cmd`) or PowerShell **as Administrator** and run the following commands sequentially:

# 
2. Install Dependencies

Run this command to install all required security and Windows interaction libraries:
    py -m pip install -r requirements.txt
      PythonForWindows==1.0.4
      cryptography>=41.0.0
       pycryptodome>=3.19.0
      pywin32>=306
