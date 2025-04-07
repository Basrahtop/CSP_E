import os
import json
import base64
import sqlite3
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher

# Constants for AES Encryption
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16

# Initialize Argon2 hasher for passphrase security
ph = PasswordHasher()

# Secure SQLite database setup
DB_FILE = "seed_security.db"

def initialize_db():
    """Initialize the database and table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS mappings (
                    id INTEGER PRIMARY KEY,
                    encrypted_data TEXT NOT NULL,
                    passphrase_hash TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def derive_key(passphrase, salt):
    """Generate a secure key from a passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(plaintext, passphrase):
    """Encrypts data using AES-256-GCM."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    encrypted_blob = {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    return json.dumps(encrypted_blob)

def decrypt_data(encrypted_blob, passphrase):
    """Decrypts AES-256-GCM encrypted data."""
    try:
        blob = json.loads(encrypted_blob)
        salt = base64.b64decode(blob["salt"])
        iv = base64.b64decode(blob["iv"])
        ciphertext = base64.b64decode(blob["ciphertext"])
        
        key = derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode()
    except Exception as e:
        return None  # Decryption failed

def save_mapping(encrypted_data, passphrase):
    """Stores encrypted data and hashed passphrase in SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    passphrase_hash = ph.hash(passphrase)
    
    c.execute("INSERT INTO mappings (encrypted_data, passphrase_hash) VALUES (?, ?)", 
              (encrypted_data, passphrase_hash))
    conn.commit()
    conn.close()

def retrieve_mapping(passphrase):
    """Retrieves and decrypts mapping from the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT encrypted_data, passphrase_hash FROM mappings")
    row = c.fetchone()
    
    conn.close()
    
    if row:
        encrypted_data, stored_hash = row
        try:
            ph.verify(stored_hash, passphrase)
            return decrypt_data(encrypted_data, passphrase)
        except:
            return None  # Invalid passphrase
    return None  # No data found

def main():
    initialize_db()

    print("\n=== Seed Phrase Security CLI Tool ===")
    while True:
        print("\n1. Secure Seed Phrase")
        print("2. Recover Seed Phrase")
        print("3. Exit")
        choice = input("\nSelect an option: ")

        if choice == "1":
            seed_phrase = input("\nEnter your 12-word seed phrase: ").strip()
            print("Enter 3 or more words to replace (comma-separated):")
            custom_replacements = input().strip().split(",")
            
            mapping = {}
            for word in custom_replacements:
                replacement = input(f"Enter replacement for '{word.strip()}': ").strip()
                mapping[word.strip()] = replacement
            
            modified_phrase = seed_phrase
            for original, replacement in mapping.items():
                modified_phrase = modified_phrase.replace(original, replacement)
            
            passphrase = getpass("\nCreate a secure passphrase: ")
            encrypted_data = encrypt_data(json.dumps({"mapping": mapping, "phrase": modified_phrase}), passphrase)

            save_mapping(encrypted_data, passphrase)
            print("\n✅ Seed phrase secured successfully!")

        elif choice == "2":
            passphrase = getpass("\nEnter your passphrase: ")
            decrypted_data = retrieve_mapping(passphrase)

            if decrypted_data:
                data = json.loads(decrypted_data)
                print("\n🔓 Your original seed phrase:")
                print(data["phrase"])
                print("\nMapping for recovery:", data["mapping"])
            else:
                print("\n❌ Incorrect passphrase or no data found.")

        elif choice == "3":
            print("\nExiting...\n")
            break
        else:
            print("\nInvalid choice! Try again.")

if __name__ == "__main__":
    main()
