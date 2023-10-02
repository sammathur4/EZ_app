# """import os
# from flask import request, jsonify, url_for, send_from_directory, send_file, make_response
# from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
# from werkzeug.utils import secure_filename
# import random
# import string
# import bcrypt
# from flask_jwt_extended import JWTManager
# from app import app, mongo
# from itsdangerous import URLSafeTimedSerializer, BadSignature
#
# # Secret key for signing the URL (keep this secret)
# SECRET_KEY = 'your-secret-key'  # Replace with your secret key
# # Create a URL serializer with the secret key
# url_serializer = URLSafeTimedSerializer(SECRET_KEY)
#
#
# # Define allowed file extensions for uploads
# ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
#
# app.config["JWT_SECRET_KEY"] = "super-secret"
# # Initialize the JWTManager with your Flask app
# jwt = JWTManager(app)
#
#
# # Function to generate a random filename
# def generate_filename():
#     return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
#
#
# # Function to check if a filename has an allowed extension
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#
#
# def hash_password(password):
#     # Generate a salt and hash the password
#     salt = bcrypt.gensalt()
#     hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
#     return hashed_password
#
#
# def verify_password(input_password, stored_hashed_password):
#     # Verify the input password against the stored hashed password
#     return bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password)
#
#
# # Function to generate a random key (e.g., "assignmentkey")
# def generate_random_key(length=12):
#     letters_and_digits = string.ascii_letters + string.digits
#     return ''.join(random.choice(letters_and_digits) for i in range(length))
#
#
# # Registration Endpoint
# @app.route('/signup', methods=['POST'])
# def signup():
#     # Parse user registration data from the request
#     data = request.get_json()
#     username = data.get('username')
#     email = data.get('email')
#     password = data.get('password')
#     user_type = data.get('user_type')  # 'ops' or 'client'
#
#     # Check if the user_type is valid ('ops' or 'client')
#     if user_type not in ['ops', 'client']:
#         return jsonify(message="Invalid user_type"), 400
#
#     # Create a User object and store it in the database
#     # Make sure to hash the password before storing it
#     # Add user_type to the User object
#     user = {
#         'username': username,
#         'email': email,
#         'password': hash_password(password),
#         'user_type': user_type
#     }
#     mongo.db.users.insert_one(user)
#
#     # Issue a JWT token upon successful registration
#     access_token = create_access_token(identity=username)
#     return jsonify(access_token=access_token), 201
#
#
# # Login Endpoint
# @app.route('/login', methods=['POST'])
# def login():
#     # Parse user login credentials from the request
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#
#     # Validate user credentials (replace with your authentication logic)
#     user = mongo.db.users.find_one({'username': username})
#
#     if user and verify_password(password, user['password']):
#         # Issue a JWT token upon successful login
#         access_token = create_access_token(identity=username)
#         return jsonify(access_token=access_token), 200
#     else:
#         return jsonify(message="Invalid credentials"), 401
#
#
# @app.route('/upload-file', methods=['POST'])
# @jwt_required()
# def upload_file():
#     # Get the user's identity from the JWT token
#     user_id = get_jwt_identity()
#     print(user_id)
#
#     # Fetch the user's role from your user database (replace with your user model)
#     user = mongo.db.users.find_one({'username': user_id})
#
#     if not user:
#         return jsonify(message="User not found"), 404
#
#     user_role = user.get('user_type')
#     print(user_role)
#
#     # Check if the user has the 'OPS' role to allow file uploads
#     if user_role.lower() == 'OPS'.lower():
#         # Implement file upload logic for OPS users
#         if 'file' not in request.files:
#             return jsonify(message="No file part"), 400
#
#         file = request.files['file']
#
#         if file.filename == '':
#             return jsonify(message="No selected file"), 400
#
#         if not allowed_file(file.filename):
#             return jsonify(message="File type not allowed"), 400
#
#         filename = secure_filename(generate_filename() + file.filename)
#         # filepath = os.path.join('uploaded_data', filename)
#         # Assign a random "assignmentid" to the file
#         assignmentid = generate_random_key(length=12)  # Generate a random assignmentid
#
#         # Save the uploaded file with the assignmentid in the filename
#         filename_with_assignmentid = f'{assignmentid}_{filename}'
#         file.save(os.path.join('uploaded_data', filename_with_assignmentid))
#
#         return jsonify(message="File uploaded successfully"), 200
#     else:
#         return jsonify(message="Access denied. You are not authorized to upload files."), 403
#
#
# @app.route('/list-files', methods=['GET'])
# @jwt_required()
# def list_files():
#     # List all files in the "uploaded_data" directory
#     uploaded_files = []
#     upload_directory = 'uploaded_data'
#
#     for filename in os.listdir(upload_directory):
#         uploaded_files.append(filename)
#
#     return jsonify(uploaded_files=uploaded_files), 200
#
#
# # @app.route('/downloads_og/<assignmentid>', methods=['GET'])
# # @jwt_required()
# # def downloads_og(assignmentid):
# #     try:
# #         # Get the user's identity from the JWT token
# #         user_id = get_jwt_identity()
# #         print(user_id)
# #         # Fetch the user's role from your user database (replace with your user model)
# #         user = mongo.db.users.find_one({'username': user_id})
# #
# #         if not user:
# #             return jsonify(message="User not found"), 404
# #
# #         user_role = user.get('user_type')
# #         print(user_role)
# #
# #         # Check if the user has the 'OPS' role to allow file uploads
# #         if user_role.lower() == 'client':
# #             matching_files = []
# #             upload_directory = 'app/uploaded_data'
# #
# #             for filename in os.listdir(upload_directory):
# #                 if filename.startswith(f'{assignmentid}'):
# #                     matching_files.append(filename)
# #
# #             # Check if any matching files were found
# #             if not matching_files:
# #                 return jsonify(message="No files found for the provided assignmentkey"), 404
# #
# #             # Create a JSON response with a custom message
# #             response = make_response(jsonify(message="File downloaded successfully", filename=matching_files[0]))
# #
# #             # Set a content-disposition header to trigger the file download
# #             response.headers["Content-Disposition"] = f"attachment; filename={matching_files[0]}"
# #
# #             # Return the response
# #             return response
# #
# #
# #             # return send_file(f'uploaded_data/{matching_files[0]}', as_attachment=True)
# #         else:
# #             return jsonify(message="Access denied")
# #
# #
# #     except Exception as e:
# #         return jsonify(message=f"An error occurred: {str(e)}"), 500
#
#
# @app.route('/downloads/<assignmentid>', methods=['GET'])
# @jwt_required()
# def api1(assignmentid):
#     try:
#         # Get the user's identity from the JWT token
#         user_id = get_jwt_identity()
#         print(user_id)
#         # Fetch the user's role from your user database (replace with your user model)
#         user = mongo.db.users.find_one({'username': user_id})
#
#         if not user:
#             return jsonify(message="User not found"), 404
#
#         user_role = user.get('user_type')
#         print(user_role)
#
#         # Check if the user has the 'OPS' role to allow file downloads
#         if user_role.lower() == 'client':
#             matching_files = []
#             upload_directory = 'uploaded_data'
#
#             for filename in os.listdir(upload_directory):
#                 if filename.startswith(f'{assignmentid}'):
#                     matching_files.append(filename)
#
#             # Check if any matching files were found
#             if not matching_files:
#                 return jsonify(message="No files found for the provided assignmentkey"), 404
#
#             # Generate a download link with a custom message
#             download_link = f"/download_file/{matching_files[0]}"
#             message = "Click the link to download your file."
#
#             # Create a JSON response with the message and download link
#             response_data = {
#                 'message': message,
#                 'download_link': download_link,
#                 'filename': matching_files[0]  # Include the filename for reference
#             }
#
#             return jsonify(response_data)
#
#         else:
#             return jsonify(message="Access denied")
#
#     except Exception as e:
#         return jsonify(message=f"An error occurred: {str(e)}"), 500
#
#
# @app.route('/download_file/<filename>', methods=['GET'])
# def download_file(filename):
#     try:
#         # Replace 'path/to/your/local/file' with the actual path to your local file
#         file_path = f'uploaded_data/{filename}'
#         # Create a JSON response with a custom message
#         response = make_response(jsonify(message="File downloaded successfully", filename=filename))
#
#         # Set a content-disposition header to trigger the file download
#         response.headers["Content-Disposition"] = f"attachment; filename={filename}"
#
#         # Use send_file to send the file for download
#         return send_file(file_path, as_attachment=True)
#
#     except Exception as e:
#         return jsonify(message=f"An error occurred: {str(e)}"), 500
# """
#
#
#
# from import_files import *
#
#
# download_link = f"/download_file/SAM"+ "-Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY5NjE4ODQ5NywianRpIjoiNTQwZTYyY2QtNzI4YS00NDdkLTlkZTAtYzIxNzViNGFhOTlmIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InNhbTEyMzQ1IiwibmJmIjoxNjk2MTg4NDk3LCJleHAiOjE2OTYxODkzOTd9.5OafKvFjA-Un4cec3-b_VslQfAhc46DfHMl3DRBqPsU"
# val1 = encrypt_url(download_link)
# print(val1)
#
# val2 = decrypt_url(val1)
# print(val2)
#
#
# def encode(input_string):
#     # Define a mapping of characters to letters
#     char_to_letter = {
#         'a': 'X',
#         'b': 'Y',
#         'c': 'Z',
#         'd': 'A',
#         'e': 'B',
#         'f': 'C',
#         'g': 'D',
#         'h': 'E',
#         'i': 'F',
#         'j': 'G',
#         'k': 'H',
#         'l': 'I',
#         'm': 'J',
#         'n': 'K',
#         'o': 'L',
#         'p': 'M',
#         'q': 'N',
#         'r': 'O',
#         's': 'P',
#         't': 'Q',
#         'u': 'R',
#         'v': 'S',
#         'w': 'T',
#         'x': 'U',
#         'y': 'V',
#         'z': 'W',
#         ' ': ' ',
#     }
#
#     # Encode the input string using the mapping
#     encoded_string = ''.join(char_to_letter.get(char, char) for char in input_string.lower())
#
#     return encoded_string
#
#
# def decode(encoded_string):
#     # Define the reverse mapping
#     letter_to_char = {
#         'X': 'a',
#         'Y': 'b',
#         'Z': 'c',
#         'A': 'd',
#         'B': 'e',
#         'C': 'f',
#         'D': 'g',
#         'E': 'h',
#         'F': 'i',
#         'G': 'j',
#         'H': 'k',
#         'I': 'l',
#         'J': 'm',
#         'K': 'n',
#         'L': 'o',
#         'M': 'p',
#         'N': 'q',
#         'O': 'r',
#         'P': 's',
#         'Q': 't',
#         'R': 'u',
#         'S': 'v',
#         'T': 'w',
#         'U': 'x',
#         'V': 'y',
#         'W': 'z',
#         ' ': ' ',
#     }
#
#     # Decode the encoded string using the reverse mapping
#     decoded_string = ''.join(letter_to_char.get(letter, letter) for letter in encoded_string.upper())
#
#     return decoded_string
#
#
# # Example usage:
# original_string = download_link
# encoded_string = encode(original_string)
# decoded_string = decode(encoded_string)
#
# print("Original String:", original_string)
# print("Encoded String:", encoded_string)
# print("Decoded String:", decoded_string)
#
# # Verify if the decoded string matches the original string
# if original_string == decoded_string:
#     print("Decoding successful!")
# else:
#     print("Decoding failed!")

from cryptography.fernet import Fernet

# Generate a secret key for URL encryption
URL_ENCRYPTION_KEY = b'VzHyw3pXNr6yMG1HTRkNta0bm2RQcRPxGnT3wln2Dgg='
fernet = Fernet(URL_ENCRYPTION_KEY)

def encrypt_url(url):
    print(type(url))
    if url == '' or type(url) is not str:
        raise ValueError("Wrong URL")

    encrypted_url = fernet.encrypt(url.encode()).decode()
    return encrypted_url


val = encrypt_url(1234)
print(val)