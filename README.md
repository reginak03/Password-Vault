# Password Vault

## Description
A secure password manager application that uses encryption and a local database (`SQLite`) to store credentials securely with a tkinter GUI. 

## Functionalities Implemented
- Master password that unlocks access to the vault and decrypts stored user credentials
- CRUD functionalities to add, edit and delete credentials
- Password generator and ability to copy it to the clipboard
- Embedded SQLite database that stores the site, username, password and notes of the user for each new entry

## Instructions
- Upon running the application, the user is asked to enter a master password. This password will be used to encrypt and decrypt passwords, as well as unlock the vault
- The interface provides the user with options to add new credentials, generate a strong password, or open the vault
- Upon opening the vault, the user credentials are shown but with the passwords encrypted., 
- If the user wishes to see the passwords decrypted, they will have to enter the master password, after which they will also have the ability to edit or delete existing entries in the database, as well as export their credentials to an encrypted .txt file

## How the master password works:
- First time = user sets their password.
- Password is saved as a hash for security.
- Later uses = compare entered password’s hash with stored one.
- Encryption & decryption key is derived from password using Fernet.
- Once the user enters the correct master password (checked by checking the stored hash with the newly calculated hash):
    - key = derive_key(master_password)
    - fernet = Fernet(key)
    - Then we can:
        fernet.encrypt(b"my_password")
        fernet.decrypt(encrypted_password_blob)

- Security goal: Only the correct master password can recreate the Fernet key and decrypt the data.
- If the password is wrong, decryption fails ([Decryption Failed]).

- When a user enters a master password:
    - hash_password checks if it’s the correct password (by comparing hashes).
    - derive_key generates a cryptographic key and uses it with Fernet to decrypt the user's stored credentials.