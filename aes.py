from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv() 

def encrypt_aes(plaintext, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Pad the plaintext to the block size of AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the IV and ciphertext
    return iv, ciphertext

def decrypt_aes(ciphertext, key, iv):
    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

    return plaintext
def save_keys_and_ciphertext(ciphertext,iv,key):
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a directory on the desktop to store keys and ciphertext
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    directory_name = os.path.join(desktop_path, f"A_keys_and_ciphertext_{current_datetime}")

    # Create the directory
    os.makedirs(directory_name) 

   
    # Save recipient's  key to a file 
    
    with open(os.path.join(directory_name, "encrypted_key.pem"), "wb") as f:
        f.write(key)

    # Save ciphertext to a file
    with open(os.path.join(directory_name, f"A_ciphertext_{current_datetime}.txt"), "wb") as f:
        f.write(ciphertext)
    # Save iv to a file
    with open(os.path.join(directory_name, f"cipher4.txt"), "wb") as f:
        f.write(iv)


def aesInitial(plaintext):
    key = os.urandom(32)  # AES-256 key

    plaintext = plaintext.encode('utf-8')

    # Encrypt the plaintext
    iv, ciphertext = encrypt_aes(plaintext, key)

    #save 
    save_keys_and_ciphertext(ciphertext, iv, key)

    return ciphertext

def aesDinitial(filename_):

    directory_name = f"A_keys_and_ciphertext_{filename_}" # Replace with the actual directory name
    path = os.getenv("path")
    directory_name = os.path.join(path, directory_name)

    # Load keys and ciphertext
    key, ciphertext,iv = load_keys_and_ciphertext(directory_name,filename_)

    # Decrypt using the loaded keys
    decrypted_text = decrypt_aes(ciphertext,key,iv)
   
    return decrypted_text


def load_keys_and_ciphertext(directory_name,filename_):

    # Load encrypted key
    with open(os.path.join(directory_name, "encrypted_key.pem"), "rb") as f:
        encrypted_key = f.read()

    # Load ciphertext
    with open(os.path.join(directory_name, f"A_ciphertext_{filename_}.txt"), "rb") as f:
        ciphertext = f.read()

     # Load cipher4
    with open(os.path.join(directory_name, f"cipher4.txt"), "rb") as f:
        iv = f.read()

    return  encrypted_key, ciphertext,iv

