import os
import hashlib
import base64

MASTER_HASH_FILE = "master.hash"

#for authentication (verifying the master password)- returns a SHA-256 hash of the given password for comparison with the hash of the stored master password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#for encrypting/decrypting vault data- returns a Fernet key from the master password (generates a 32-byte Fernet key from the master password)
def derive_key(password):
    sha = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(sha)

def is_master_password_set():
    return os.path.exists(MASTER_HASH_FILE)

def save_master_password(password):
    hashed = hash_password(password)
    with open(MASTER_HASH_FILE, "w") as f:
        f.write(hashed)

def check_master_password(password):
    if not is_master_password_set():
        return False
    hashed = hash_password(password)
    with open(MASTER_HASH_FILE, "r") as f:
        stored_hash = f.read().strip() #store the hash of the master password in master.hash to prevent attackers from knowing the master password, even if master.hash is stolen
    return hashed == stored_hash

# key = Fernet.generate_key() #generate AES 128 bit key
# with open("key.key", "wb") as key_file:
#     key_file.write(key)

# #load key later
# with open("key.key", "rb") as key_file:
#     key = key_file.read()

# fernet = Fernet(key)

# #encrypt
# enc_password = fernet.encrypt(b"mysecretpassword")

# #decrypt
# dec_password = fernet.decrypt(enc_password)
# print(dec_password.decode())

# conn = sqlite3.connect("vault.db") #connect to sqlite database
# cursor = conn.cursor()

# def derive_key(password):
#     """Derive a Fernet key from the user’s password using SHA-256."""
#     sha = hashlib.sha256(password.encode()).digest()
#     return base64.urlsafe_b64encode(sha)