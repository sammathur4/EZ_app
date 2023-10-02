import os
import secrets
import re
import threading
from flask import request, jsonify, url_for, send_from_directory, send_file, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import random
import string
import bcrypt
from flask_jwt_extended import JWTManager



from flask import Flask
from pymongo import MongoClient


app = Flask(__name__)
"mongodb+srv://sammathur4:wo7kdLODmeaFG7wL@optionaro.gpzp2ko.mongodb.net/"
MONGODB_URI = 'mongodb://localhost:27017/your_database'
mongo = MongoClient(MONGODB_URI)

from itsdangerous import URLSafeTimedSerializer, BadSignature, URLSafeSerializer
from cryptography.fernet import Fernet, InvalidToken

# Generate a secret key for URL encryption
URL_ENCRYPTION_KEY = b'VzHyw3pXNr6yMG1HTRkNta0bm2RQcRPxGnT3wln2Dgg='
fernet = Fernet(URL_ENCRYPTION_KEY)
SECRET_KEY = '483101b443f2085ad5e30fc3d1f3f3d75575f23fc4dac292f805c3df1494e4ec'  # Replace with your secret key
app.config["JWT_SECRET_KEY"] = "7420602992a1e37ba13f6824de6ae5149246d1c550b16093f2d49937d8b507f8"
URL_SECRET_KEY = 'your-secret-key'
url_serializer = URLSafeTimedSerializer(SECRET_KEY)
ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
jwt = JWTManager(app)
# Create a collection for verification tokens
verification_tokens_collection = mongo.db.verification_tokens_collection

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Encrypt the download URL
def encrypt_url(url):
    print(type(url))
    if url == '':
        raise ValueError()
    if type(url) is not str:
        raise AttributeError()

    encrypted_url = fernet.encrypt(url.encode()).decode()
    return encrypted_url


# Decrypt the download URL
def decrypt_url(encrypted_url):
    if not encrypted_url:
        raise ValueError("URL cannot be empty")

    if not isinstance(encrypted_url, str):
        raise TypeError("URL must be a string")

    decrypted_url = fernet.decrypt(encrypted_url.encode()).decode()
    return decrypted_url


# Function to generate a random filename
def generate_filename():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))


# Function to check if a filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def hash_password(password):
    if password is None or password==None:
        raise ValueError()

    if password == '':
        raise TypeError()

    if not isinstance(password, str):
        raise TypeError


    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def verify_password(input_password, stored_hashed_password):
    # Verify the input password against the stored hashed password
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password)


def generate_random_key(length=12):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))


# Function to generate a verification token (random string)
def generate_verification_token():
    return secrets.token_urlsafe(32)
