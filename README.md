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
py -m pip install -r requirements.txt
