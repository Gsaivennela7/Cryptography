from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

import base64
from stegano import lsb
import time
from rsa_aes import initial,dinitial
import os

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'  # Set to a random value

# Setup MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['user_database']
users = db['users']

@app.route('/', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = users.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        return redirect(url_for('home'))
    return 'Invalid username/password'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        users.insert_one({'username': username, 'email': email, 'password': hashed_password})
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login_page'))
    return render_template('signup.html')

def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        return result, elapsed_time
    return wrapper

@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/encrypt', methods=['GET'])
def encrypt_form():
    return render_template('encrypt.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form['text']
    algorithm = request.form['algorithm']

    result = perform_encryption(plaintext, algorithm)
    
    return render_template('result.html', result=result, time=123)

@app.route('/decrypt', methods=['GET'])
def decrypt_form():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Check if a file was uploaded
    if 'file' not in request.files:
        return "No file provided for decryption."

    file = request.files['file']

    filename_ = file.filename

    # Check if the file has a name and is not empty
    if filename_ == '':
        return "Invalid file name."
    split_result = filename_.split('_',1)
    split_result = split_result[1].split('.',1)
    parent_directory =  split_result[0]

    algorithm = request.form['algorithm']

    result = perform_decryption( algorithm, parent_directory)

    return render_template('result.html', result=result, time=123)

def perform_encryption(plaintext, algorithm):
    if algorithm == 'aes':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == '3des':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == 'aes_rsa':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == 'dh':
        secret_message = 'YourSecretMessage'
        encoded_image = lsb.hide('path/to/your/image.png', secret_message)
        return "Steganography successful!", 0
    else:
        return "Invalid algorithm", 0

def perform_decryption(algorithm, parent_directory):
    if algorithm == 'aes':
        initial(cipherText)
        return decrypted_text.decode(), 0
    elif algorithm == '3des':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == 'aes_rsa':
        print("hdsdu",parent_directory)
        plainText = dinitial(parent_directory)
        return palinText
    elif algorithm == 'dh':
        decoded_message = lsb.reveal('path/to/your/image.png')
        return decoded_message
    else:
        return "Invalid algorithm", 0

if __name__ == '__main__':
    app.run(debug=True)