from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from stegano import lsb
import time
from rsa_aes import initial

app = Flask(__name__)

def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        return result, elapsed_time
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET'])
def encrypt_form():
    return render_template('encrypt.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form['text']
    algorithm = request.form['algorithm']

    result, elapsed_time = perform_encryption(plaintext, algorithm)
    
    return render_template('result.html', result=result, time=elapsed_time)

@app.route('/decrypt', methods=['GET'])
def decrypt_form():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form['text']
    algorithm = request.form['algorithm']

    result, elapsed_time = perform_decryption(ciphertext, algorithm)

    return render_template('result.html', result=result, time=elapsed_time)

def perform_encryption(plaintext, algorithm):
    if algorithm == 'aes':
    
    elif algorithm == 'dh':
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key.decode(), 0
    elif algorithm == 'steganography':
        secret_message = 'YourSecretMessage'
        encoded_image = lsb.hide('path/to/your/image.png', secret_message)
        return "Steganography successful!", 0
    else:
        return "Invalid algorithm", 0

def perform_decryption(ciphertext, algorithm):
    if algorithm == 'aes':
        key = b'SuperSecretKey12'  # Replace with a secure key management mechanism
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(base64.b64decode(ciphertext.encode())) + decryptor.finalize()
        return decrypted_text.decode(), 0
    elif algorithm == 'dh':
        return "Decryption not applicable for Diffie-Hellman", 0
    elif algorithm == 'steganography':
        decoded_message = lsb.reveal('path/to/your/image.png')
        return decoded_message, 0
    else:
        return "Invalid algorithm", 0

if __name__ == '__main__':
    app.run(debug=True)