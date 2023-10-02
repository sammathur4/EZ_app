from import_files import *


def send_email(server, sender_email, to_email, email_message):
    server.sendmail(sender_email, to_email, email_message)
    server.quit()


def validate_email(to_email):
    # Regular expression pattern for a valid email address
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

    # Use re.match to check if the email matches the pattern
    if re.match(email_pattern, to_email):
        return True
    else:
        return False

def send_verification_email(to_email, verification_token):
    if not validate_email(to_email):
        raise ValueError("Invalid email address")
    # Set your Gmail email address and password
    sender_email = 'your_email@gmail.com'
    sender_password = 'your_password'

    # Create a message object
    msg = MIMEMultipart()

    # Add sender and recipient email addresses
    msg['From'] = sender_email
    msg['To'] = to_email

    # Set the email subject
    msg['Subject'] = 'Email Verification'

    # Create the email body with the verification token
    email_body = f'Please click the following link to verify your email: '
    email_body += f'verification_token={verification_token}'

    # Attach the email body as plain text
    msg.attach(MIMEText(email_body, 'plain'))

    # Connect to the Gmail SMTP server
    try:
    #     server = smtplib.SMTP('smtp.gmail.com', 587)
    #     server.starttls()
    #     server.login(sender_email, sender_password)
    #
    #     # Send the email
    #     server.sendmail(sender_email, to_email, msg.as_string())
    #     server.quit()
    #
    #     print(f'Verification email sent to {to_email}')
    #     return 'success'
    # except Exception as e:
    #     print(f'Error sending email: {str(e)}')
    #     return 'failure'
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        # Send the email in a separate worker or background job
        send_email_worker = threading.Thread(target=send_email, args=(server, sender_email, to_email, msg.as_string()))
        send_email_worker.start()

        print(f'Verification email sent to {to_email}')
    except Exception as e:
        print(f'Error sending email: {str(e)}')


# Registration Endpoint
@app.route('/signup', methods=['POST'])
def signup():
    # Parse user registration data from the request
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type')  # 'ops' or 'client'

    # Check if the user_type is valid ('ops' or 'client')
    if user_type not in ['ops', 'client']:
        return jsonify(message="Invalid user_type"), 400

    # Check if the username or email already exists in the database
    existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
    if existing_user:
        return jsonify(message="Username or email already exists"), 409

    # Validate the email address
    if not validate_email(email):
        return jsonify(message="Invalid email address"), 400

    user = {
        'username': username,
        'email': email,
        'password': hash_password(password),
        'user_type': user_type,
        'verified': False  # Set verified to False initially
    }
    try:
        mongo.db.users.insert_one(user)
    except Exception as e:
        print(f'Error inserting user into database: {str(e)}')

    if user_type == 'client':
        # Generate a verification token and store it in MongoDB
        verification_token = generate_verification_token()
        verification_tokens_collection.insert_one({'email': email, 'token': verification_token})

        # Send a verification email to the user
        send_verification_email(email, verification_token)  # Implement this function to send the email

    # Issue a JWT token upon successful registration
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 201


# Email Verification Endpoint
@app.route('/verify_email', methods=['POST'])
def verify_email():
    # Parse email and verification token from the request
    data = request.get_json()
    email = data.get('email')
    verification_token = data.get('verification_token')

    # Check if the email and verification token match
    stored_token = verification_tokens_collection.find_one({'email': email})

    if stored_token and stored_token['token'] == verification_token:
        # Update the user's 'verified' status to True
        mongo.db.users.update_one({'email': email}, {'$set': {'verified': True}})
        # Remove the verification token from MongoDB
        verification_tokens_collection.delete_one({'email': email})
        return jsonify(message="Email verified successfully"), 200
    else:
        return jsonify(message="Invalid verification token"), 400


# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    # Parse user login credentials from the request
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validate user credentials (replace with your authentication logic)
    user = mongo.db.users.find_one({'username': username})

    if user and verify_password(password, user['password']):
        # Issue a JWT token upon successful login
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="Invalid credentials"), 401


@app.route('/upload-file', methods=['POST'])
@jwt_required()
def upload_file():
    # Get the user's identity from the JWT token
    user_id = get_jwt_identity()
    print(user_id)

    # Fetch the user's role from your user database (replace with your user model)
    user = mongo.db.users.find_one({'username': user_id})

    if not user:
        return jsonify(message="User not found"), 404

    user_role = user.get('user_type')
    print(user_role)

    # Check if the user has the 'OPS' role to allow file uploads
    if user_role.lower() == 'OPS'.lower():
        # Implement file upload logic for OPS users
        if 'file' not in request.files:
            return jsonify(message="No file part"), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify(message="No selected file"), 400

        if not allowed_file(file.filename):
            return jsonify(message="File type not allowed"), 400

        filename = secure_filename(generate_filename() + file.filename)

        # Assign a random "assignmentid" to the file
        assignmentid = generate_random_key(length=12)  # Generate a random assignmentid

        # Save the uploaded file with the assignmentid in the filename
        filename_with_assignmentid = f'{assignmentid}_{filename}'
        file.save(os.path.join('uploaded_data', filename_with_assignmentid))

        return jsonify(message="File uploaded successfully"), 200
    else:
        return jsonify(message="Access denied. You are not authorized to upload files."), 403


@app.route('/list-files', methods=['GET'])
@jwt_required()
def list_files():
    # List all files in the "uploaded_data" directory
    uploaded_files = []
    upload_directory = 'uploaded_data'

    for filename in os.listdir(upload_directory):
        uploaded_files.append(filename)

    return jsonify(uploaded_files=uploaded_files), 200


@app.route('/downloads/<assignmentid>', methods=['GET'])
@jwt_required()
def download_url_gen(assignmentid):
    try:
        # Get the raw JWT token from the request headers
        raw_token = request.headers.get('Authorization')

        # Get the user's identity from the JWT token
        user_id = get_jwt_identity()
        print(user_id)
        # Fetch the user's role from your user database (replace with your user model)
        user = mongo.db.users.find_one({'username': user_id})

        if not user:
            return jsonify(message="User not found"), 404

        user_role = user.get('user_type')
        print(user_role)

        # Check if the user has the 'OPS' role to allow file downloads
        if user_role.lower() == 'client':
            matching_files = []
            upload_directory = 'uploaded_data'

            for filename in os.listdir(upload_directory):
                if filename.startswith(f'{assignmentid}'):
                    matching_files.append(filename)

            # Check if any matching files were found
            if not matching_files:
                return jsonify(message="No files found for the provided assignment key"), 404

            # Generate a download link with a custom message
            download_link = f"/download_file/{matching_files[0]}" + f"-break{user_id}"
            safe_url = encrypt_url(download_link)
            message = "Click the link to download your file."

            # Create a JSON response with the message and download link
            response_data = {
                'message': message,
                'download_link': safe_url,
                'filename': matching_files[0]  # Include the filename for reference
            }

            return jsonify(response_data)
        else:
            return jsonify(message="Access denied")

    except Exception as e:
        return jsonify(message=f"An error occurred: {str(e)}"), 500


@app.route('/download_file/<encrypted_url>', methods=['GET'])
@jwt_required()
def download_file(encrypted_url):
    try:
        # Get the raw JWT token from the request headers
        raw_token = request.headers.get('Authorization')
        # Get the user's identity from the JWT token
        user_id = get_jwt_identity()
        print(user_id)
        # Fetch the user's role from your user database (replace with your user model)
        user = mongo.db.users.find_one({'username': user_id})

        if not user:
            return jsonify(message="User not found"), 404

        user_role = user.get('user_type')
        user_name = user.get('username')
        print(user_role)

        if user_role.lower() == 'client':

            download_url = decrypt_url(encrypted_url)
            print("Downloading file", download_url)

            # download_url, download_url_username = download_url.split('-break')
            username_start = download_url.rfind('/') + 1
            username_end = download_url.find('-', username_start)
            download_url_username = download_url[username_start:username_end]

            print("--------------")
            print(user_name)
            print()
            print(f' {download_url_username}')
            print(user_name == f'{download_url_username}')
            print("--------------")
            if user_name == f'{download_url_username}':
                print("Downloading file 2", download_url)

                url_components = download_url.split('/')
                assignment_id = url_components[-2]  # Assuming assignment_id is the second-to-last component
                filename = url_components[-1]

                # Get the user's identity from the JWT token
                user_id = get_jwt_identity()
                print(user_id)
                # Fetch the user's role from your user database (replace with your user model)
                user = mongo.db.users.find_one({'username': user_id})
                user_role = user.get('user_type')
                print(user_role)

                # Check if the user has the 'OPS' role to allow file downloads
                if user_role.lower() == 'client':
                    # Replace 'path/to/your/local/file' with the actual path to your local file
                    file_path = os.path.join('uploaded_data', filename)
                    # Create a JSON response with a custom message
                    response = make_response(jsonify(message="File downloaded successfully", filename=filename))

                    # Set a content-disposition header to trigger the file download
                    response.headers["Content-Disposition"] = f"attachment; filename={filename}"

                    # Use send_file to send the file for download
                    return send_file(file_path, as_attachment=True)
                else:
                    return jsonify(message="Access denied"), 404
            else:
                return jsonify(message="Access denied"), 404
        else:
            return jsonify(message="Access denied"), 404

    except Exception as e:
        return jsonify(message=f"An error occurred: {str(e)}"), 500







