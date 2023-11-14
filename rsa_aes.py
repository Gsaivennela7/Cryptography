from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
import os
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, recipient_public_key):

    print(aes_key," .  aes key")
    cipherKey = recipient_public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(cipherKey," .  aes key")
    return cipherKey



def aes_encrypt(plaintext, aes_key):
   # Ensure that plaintext is of type bytes
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')  # Assuming plaintext is a string, encode it to bytes

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def save_keys_and_ciphertext(ciphertext, encrypted_aes_key, recipient_private_key):
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a directory on the desktop to store keys and ciphertext
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    directory_name = os.path.join(desktop_path, f"keys_and_ciphertext_{current_datetime}")

    # Create the directory
    os.makedirs(directory_name) 

    # Save encrypted AES key to a file
    with open(os.path.join(directory_name, "encrypted_aes_key.txt"), "wb") as f:
        f.write(encrypted_aes_key)

    # Save recipient's private key to a file (encrypted)
    encrypted_private_key = recipient_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"your-password")
    )
    with open(os.path.join(directory_name, "encrypted_private_key.pem"), "wb") as f:
        f.write(encrypted_private_key)

    # Save ciphertext to a file
    with open(os.path.join(directory_name, f"ciphertext_{current_datetime}.txt"), "wb") as f:
        f.write(ciphertext)

    print(f"Keys and ciphertext saved to directory: {directory_name}")

def initial(plaintext):
    # Generate RSA key pair for the recipient
    recipient_private_key, recipient_public_key = generate_rsa_key_pair()

    # Generate a random AES key for the message
    aes_key = os.urandom(32)  # 256-bit key for AES-256

    # Encrypt the AES key with the recipient's public RSA key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, recipient_public_key)

    # Encrypt the actual message with the AES key
    ciphertext = aes_encrypt(plaintext, aes_key)

    save_keys_and_ciphertext(ciphertext, encrypted_aes_key, recipient_private_key)
   
    return ciphertext


def dinitial(filename_):
   # Example usage
    directory_name = f"keys_and_ciphertext_{filename_}" # Replace with the actual directory name
    
    directory_name = os.path.join("/Users/saivennelagarikapati/Desktop/", directory_name)

    print(directory_name,"directory name")
    # Load keys and ciphertext
    encrypted_aes_key, encrypted_private_key, ciphertext = load_keys_and_ciphertext(directory_name,filename_)

    # Decrypt using the loaded keys
    decrypted_text = decrypt_using_keys(encrypted_aes_key, encrypted_private_key, ciphertext)
    print("decryptin done",  decrypted_text)
    # Print or use the decrypted text as needed
    print("Decrypted Text:", decrypted_text.decode('utf-8'))


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
    with open(os.path.join(directory_name, f"ciphertext_{filename_}.txt"), "rb") as f:
        ciphertext = f.read()

    return encrypted_aes_key, encrypted_private_key, ciphertext

def decrypt_using_keys(encrypted_aes_key, encrypted_private_key, ciphertext):
    # Decrypt the recipient's private key
    private_key = decrypt_private_key(encrypted_private_key, b"your-password")

    # Decrypt the AES key with the recipient's private key
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

    # Decrypt the ciphertext using the decrypted AES key
    decrypted_text = aes_decrypt(ciphertext, aes_key)

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

def aes_decrypt(ciphertext, aes_key):
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_text

