import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def save_keys_and_ciphertext(ciphertext,shared_key_alice,public_key_alice,private_key_alice):
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a directory on the desktop to store keys and ciphertext
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    directory_name = os.path.join(desktop_path, f"E_Alice_{current_datetime}")

    # Create the directory
    os.makedirs(directory_name) 

    # Save Alice's public key to a file
    serialized_public_key = public_key_alice.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(directory_name, "public_key_alice.pem"), "wb") as f:
        f.write(serialized_public_key)


    # Save shared key to a file
    with open(os.path.join(directory_name, "shared_key_alice.txt"), "wb") as f:
        f.write(shared_key_alice)

    
    # Save recipient's private key to a file (encrypted)
    encrypted_private_key = private_key_alice.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"abc")
    )
    with open(os.path.join(directory_name, "encrypted_private_key.pem"), "wb") as f:
        f.write(encrypted_private_key)

    # Save ciphertext to a file
    with open(os.path.join(directory_name, f"E_ciphertext_{current_datetime}.txt"), "wb") as f:
        f.write(ciphertext)

    print(f"Keys and ciphertext saved to directory: {directory_name}")

def eInitial(plaintext,public_key_bob):

    # Bob generates his key pair
    private_key_alice = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_alice= private_key_alice.public_key()


    # Shared key of Alice
    shared_key_alice = private_key_alice.exchange(ec.ECDH(), public_key_bob)


    #emcode
    plaintext = plaintext.encode('utf-8')

    #encrypt
    ciphertext = aes_encrypt(plaintext,shared_key_alice)

    #save
    save_keys_and_ciphertext(ciphertext,shared_key_alice,public_key_alice,private_key_alice)

    return ciphertext  

def load_keys_and_ciphertext(alice_directory_name,directory_name,filename_):
    
    # Load shared key
    with open(os.path.join(alice_directory_name, "shared_key_alice.txt"), "rb") as f:
        shared_key_alice = f.read()

    # Load public key
    with open(os.path.join(alice_directory_name, "public_key_alice.pem"), "rb") as f:
        public_key_alice = f.read()

    # Load encrypted private key
    with open(os.path.join(directory_name, "private_key_bob.pem"), "rb") as f:
        encrypted_private_key = f.read()

    # Load ciphertext
    with open(os.path.join(alice_directory_name, f"E_ciphertext_{filename_}.txt"), "rb") as f:
        ciphertext = f.read()


    return shared_key_alice,public_key_alice,encrypted_private_key,ciphertext

def eDinitial(filename_):

    directory_name = f"E_BOB_{filename_}" # Replace with the actual directory name
    alice_directory_name = f"E_Alice_{filename_}"
    path = os.getenv("path")
    directory_name = os.path.join(path, directory_name)
    alice_directory_name = os.path.join(path, alice_directory_name)
    
    # Load keys and ciphertext
    shared_key_alice,public_key_alice,encrypted_private_key_bob,ciphertext = load_keys_and_ciphertext(alice_directory_name,directory_name,filename_);
    
    private_key_bob = decrypt_private_key(encrypted_private_key_bob, b"abc")

    
    # Deserialize the public key
    public_key_alice = serialization.load_pem_public_key(
    public_key_alice,
    backend=default_backend()
)
    # Shared key of Bob
    shared_key_bob = private_key_bob.exchange(ec.ECDH(), public_key_alice)
    
    # Verify both Alice and Bob arrived at the same shared key
    if (shared_key_alice == shared_key_bob):
        decrypted_text = aes_decrypt(shared_key_bob,ciphertext)
    
    return decrypted_text

     

def aes_encrypt(plaintext,shared_key_alice):
    
    cipher = Cipher(algorithms.AES(shared_key_alice), modes.CFB(b'\x00'*16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(shared_key_bob,ciphertext):
    cipher = Cipher(algorithms.AES(shared_key_bob), modes.CFB(b'\x00'*16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text

def getBobKey():
    

    # Bob generates his key pair
    private_key_bob = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_bob = private_key_bob.public_key()


    # private_key_bob = generate_random_p_256_secret(n)
    # public_key_bob = G * private_key_bob

    saveBobPrivateKey(private_key_bob)

    return public_key_bob


def saveBobPrivateKey(private_key_bob):
    # Get the current date and time
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a directory on the desktop to store keys and ciphertext
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    directory_name = os.path.join(desktop_path, f"E_BOB_{current_datetime}")

    # Create the directory
    os.makedirs(directory_name) 


     # Save recipient's private key to a file (encrypted)
    encrypted_private_key = private_key_bob.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"abc")
    )
    with open(os.path.join(directory_name, "private_key_bob.pem"), "wb") as f:
        f.write(encrypted_private_key)


def decrypt_private_key(encrypted_private_key, password):
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password,
        backend=default_backend()
    )
    return private_key