from flask import Flask, render_template, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from stegano import lsb
import time
from rsa_aes import initial,dinitial
from aes import aesInitial,aesDinitial
from ecdhe import eInitial,eDinitial
import os
import psutil

app = Flask(__name__)

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

    result, elapsed_time, cpu_cycles  = perform_encryption(plaintext, algorithm)
    
    return render_template('result.html', result=result, time=elapsed_time, cpu_cycles=cpu_cycles)

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
    

    split_result = filename_.split('_',2)
    split_result = split_result[2].split('.',1)
    parent_directory =  split_result[0]

    algorithm = request.form['algorithm']


    result, elapsed_time, cpu_cycles = perform_decryption( algorithm, parent_directory)
   

    return render_template('result.html', result=result, time=elapsed_time, cpu_cycles=cpu_cycles)

@measure_time
def perform_encryption(plaintext, algorithm):
    if algorithm == 'aes':
        cipherText = aesInitial(plaintext);
        return  cipherText;
    elif algorithm == 'aes_rsa':
        cipherText = initial(plaintext);
        return  cipherText;
    elif algorithm == 'dh':
        cipherText = eInitial(plaintext);
        return  cipherText;
    else:
        return "Invalid algorithm", 0

@measure_time
def perform_decryption(algorithm, parent_directory):
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

if __name__ == '__main__':
    app.run(debug=True)