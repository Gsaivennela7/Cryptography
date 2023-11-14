from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from cryptography.hazmat.primitives import serialization
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv() 


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, plaintext, recipient_public_key):

    cipherkey = recipient_public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
   # Ensure that plaintext is of type bytes
   
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16);
    cipher = Cipher(algorithms.AES(aes_key), CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data)

    return   iv,ciphertext, cipherkey

def save_keys_and_ciphertext(ciphertext,iv, encrypted_aes_key, recipient_private_key):
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a directory on the desktop to store keys and ciphertext
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    directory_name = os.path.join(desktop_path, f"H_keys_and_ciphertext_{current_datetime}")

    # Create the directory
    os.makedirs(directory_name) 

    # Save encrypted AES key to a file
    with open(os.path.join(directory_name, "encrypted_aes_key.txt"), "wb") as f:
        f.write(encrypted_aes_key)

    # Save recipient's private key to a file (encrypted)
    encrypted_private_key = recipient_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"abc")
    )
    with open(os.path.join(directory_name, "encrypted_private_key.pem"), "wb") as f:
        f.write(encrypted_private_key)

    # Save ciphertext to a file
    with open(os.path.join(directory_name, f"H_ciphertext_{current_datetime}.txt"), "wb") as f:
        f.write(ciphertext)
    # Save iv to a file
    with open(os.path.join(directory_name, f"cipher4.txt"), "wb") as f:
        f.write(iv)

def initial(plaintext):
    # Generate RSA key pair for the recipient
    recipient_private_key, recipient_public_key = generate_rsa_key_pair()

    # Generate a random AES key for the message
    aes_key = os.urandom(32)  # 256-bit key for AES-256


    plaintext = plaintext.encode('utf-8')
    
    # Encrypt the AES key with the recipient's public RSA key
    iv,ciphertext, cipherkey = encrypt_aes_key_with_rsa(aes_key,plaintext, recipient_public_key)
    
    
   
    save_keys_and_ciphertext(ciphertext, iv,cipherkey, recipient_private_key)
   
    return ciphertext


def dinitial(filename_):
  
    directory_name = f"H_keys_and_ciphertext_{filename_}" # Replace with the actual directory name
    
    path = os.getenv("path")
    directory_name = os.path.join(path, directory_name)

    print(directory_name,"directory name")
    # Load keys and ciphertext
    encrypted_aes_key, encrypted_private_key, ciphertext,iv = load_keys_and_ciphertext(directory_name,filename_)

    # Decrypt using the loaded keys
    decrypted_text = decrypt_using_keys(encrypted_aes_key, encrypted_private_key, ciphertext,iv)
   
    return decrypted_text

def load_keys_and_ciphertext(directory_name,filename_):
    try:
        with open(os.path.join(directory_name, "encrypted_aes_key.txt"), "rb") as f:
            encrypted_aes_key = f.read()
    except FileNotFoundError as e:
        print(f"Error loading 'encrypted_aes_key.txt': {e}")
    # Handle the error as needed

    # Load encrypted private key
    with open(os.path.join(directory_name, "encrypted_private_key.pem"), "rb") as f:
        encrypted_private_key = f.read()

    # Load ciphertext
    with open(os.path.join(directory_name, f"H_ciphertext_{filename_}.txt"), "rb") as f:
        ciphertext = f.read()

     # Load ciphertext
    with open(os.path.join(directory_name, f"cipher4.txt"), "rb") as f:
        iv = f.read()

    return encrypted_aes_key, encrypted_private_key, ciphertext,iv

def decrypt_using_keys(encrypted_aes_key, encrypted_private_key, ciphertext,iv):
    # Decrypt the recipient's private key
    private_key = decrypt_private_key(encrypted_private_key, b"abc")

    # Decrypt the AES key with the recipient's private key
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

    # Decrypt the ciphertext using the decrypted AES key
    decrypted_text = aes_decrypt(ciphertext, aes_key,iv)

    return decrypted_text

def decrypt_private_key(encrypted_private_key, password):
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password,
        backend=default_backend()
    )
    return private_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    oaep_padding = asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    aes_key = private_key.decrypt(encrypted_aes_key, oaep_padding)
    return aes_key

def aes_decrypt(ciphertext, recovered_key,iv):
    # Decrypt padded plaintext
    aes_cbc_cipher = Cipher(algorithms.AES(recovered_key), CBC(iv))
    recovered_padded_plaintext = aes_cbc_cipher.decryptor().update(ciphertext)

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_padded_plaintext) + pkcs7_unpadder.finalize()

    return recovered_plaintext

