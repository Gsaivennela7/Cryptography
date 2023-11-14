from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session

import base64
from stegano import lsb
import time
from rsa_aes import initial,dinitial
from aes import aesInitial,aesDinitial
from ecdhe import eInitial,eDinitial,getBobKey
from dbconfig import connectDb
import os
import psutil

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'  # Set to a random value

# Setup MongoDB connection
db = connectDb()
users = db.Users

@app.route('/', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = users.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        session['username'] = username
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
        start_cpu = psutil.cpu_percent()  # Measure CPU usage before function call
        result = func(*args, **kwargs)
        end_time = time.time()
        end_cpu = psutil.cpu_percent()  # Measure CPU usage after function call
        elapsed_time = end_time - start_time
        cpu_cycles = end_cpu - start_cpu
        return result, elapsed_time, cpu_cycles
    return wrapper

def is_valid_algorithm(filename, algorithm):
    if filename.startswith('H') and algorithm != 'aes_rsa':
        return False
    elif filename.startswith('A') and algorithm != 'aes':
        return False
    elif filename.startswith('E') and algorithm != 'dh':
        return False
    return True

@app.route('/home')
def home():
    username = session.get('username', None)  # Get the username from the session
    return render_template('index.html', username=username)


@app.route('/encrypt', methods=['GET'])
def encrypt_form():
    username = session.get('username', None)
    return render_template('encrypt.html', username=username)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form['text']
    algorithm = request.form['algorithm']
    username = session.get('username', None)
    result, elapsed_time, cpu_cycles  = perform_encryption(plaintext, algorithm,username)
    
    return render_template('result.html', result=result, time=elapsed_time, cpu_cycles=cpu_cycles, username=username)

@app.route('/decrypt', methods=['GET'])
def decrypt_form():
    username = session.get('username', None)
    return render_template('decrypt.html', username=username)

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

    algorithm = request.form['algorithm']

    if not filename_.startswith(('H', 'A', 'E')) or not is_valid_algorithm(filename_,algorithm):
        return render_template('display.html', result="Inavlid Algorithm please select Valid Algorithm")
   
    username = session.get('username', None)

    split_result = filename_.split('_',2)
    split_result = split_result[2].split('.',1)
    parent_directory =  split_result[0]

   

    result, elapsed_time, cpu_cycles = perform_decryption( algorithm, parent_directory,username)

    return render_template('result.html', result=result, time=elapsed_time, cpu_cycles=cpu_cycles,username =username)
    

@measure_time
def perform_encryption(plaintext, algorithm,username):
    if algorithm == 'aes':
        cipherText = aesInitial(plaintext);
        return  cipherText;
    elif algorithm == 'aes_rsa':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == 'dh':
        key = getBobKey();
        cipherText = eInitial(plaintext,key);
        return  cipherText;
    else:
        return "Invalid algorithm", 0

@measure_time
def perform_decryption(algorithm, parent_directory,username):
    if algorithm == 'aes':
        text = aesDinitial(parent_directory)
        return text.decode('utf-8')
    elif algorithm == 'aes_rsa':
        text = dinitial(parent_directory)
        return text.decode('utf-8')
    elif algorithm == 'dh':
        text = eDinitial(parent_directory)
        return text.decode('utf-8')
    else:
        return "Invalid algorithm", 0
    
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login_page'))


if __name__ == '__main__':
    app.run(debug=True)