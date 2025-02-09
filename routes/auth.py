from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from extensions import mongo
from models.user import User
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson.objectid import ObjectId 
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import random
import string
import time

bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate that required fields are present
    required_fields = ['email', 'password', 'confirm_password', 'full_name']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    if mongo.db.users.find_one({'email': data['email']}):
        return jsonify({'message': 'Email already exists'}), 400
    
    # Validate passwords match before hashing
    if data['password'] != data['confirm_password']:
        return jsonify({'message': 'Passwords do not match'}), 400
    
    # Only allow user role in public registration
    role = 'user'
    if 'role' in data and data['role'] == 'admin':
        # Check if admin secret key is provided and valid
        admin_key = request.headers.get('Admin-Key')
        if not admin_key or admin_key != current_app.config['ADMIN_SECRET_KEY']:
            return jsonify({'message': 'Invalid admin registration'}), 403
        role = 'admin'

    try:
        user = User(
            email=data['email'],
            password=data['password'],
            confirm_password=data['confirm_password'],
            full_name=data['full_name'],
            role=role,
            business_name=data.get('business_name')
        )
        
        # After validation succeeds, create the user dictionary with hashed password
        user_dict = user.to_dict()
        user_dict['password'] = generate_password_hash(data['password'])
        
        mongo.db.users.insert_one(user_dict)
        return jsonify({'message': 'User created successfully', 'role': role}), 201
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = mongo.db.users.find_one({'email': data['email']})
    
    if not user or not check_password_hash(user['password'], data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': str(user['_id']),
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, current_app.config['JWT_SECRET_KEY'])
    
    return jsonify({
        'token': token,
        'role': user['role'],
        'user_id': str(user['_id'])
    }), 200



@bp.route('/logout', methods=['POST'])
def logout():
    # Get the token from the JSON body
    data = request.get_json()

    # Check if token is provided in the body
    token = data.get('token')
    if not token:
        return jsonify({'message': 'No token provided'}), 401
    
    try:
        # Verify the token is valid
        jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        
        # If we get here, the token is valid
        return jsonify({
            'message': 'Successfully logged out',
            'status': 'success'
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    


@bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    
    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Generate a 6-digit OTP
    otp = ''.join(random.choices(string.digits, k=6))
    
    # Save the OTP and its expiration time in the database (e.g., 10 minutes)
    expiration_time = time.time() + 600  # OTP expires in 10 minutes
    mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'reset_otp': otp, 'otp_expiration': expiration_time}})
    
    # Send OTP via email
    send_otp_email(email, otp)

    return jsonify({'message': 'OTP sent to your email address'}), 200


def send_otp_email(email, otp):
    # SMTP configuration (you may use the same SMTP setup)
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "testampli2023@gmail.com"
    smtp_password = "cpxvsxtxfeiuahbo"
    sender_email = smtp_username

    # Email content
    subject = "Your OTP for Password Reset"
    body = f"Use the following OTP to reset your password: {otp}"

    # Construct the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, email, msg.as_string())
        print(f"OTP sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")


def send_reset_email(email, token):
    # SMTP configuration from the app configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "testampli2023@gmail.com"
    smtp_password = "cpxvsxtxfeiuahbo"
    sender_email = smtp_username

    # Email content
    subject = "Password Reset"
    body = f"Click the link to reset your password: http://127.0.0.1:5000/api/auth/reset-password/{token}"

    # Construct the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, email, msg.as_string())
        print(f"Password reset email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")



@bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')
    
    # Find the user by email
    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Check if OTP matches and hasn't expired
    if user.get('reset_otp') != otp:
        return jsonify({'message': 'Invalid OTP'}), 400
    
    if time.time() > user.get('otp_expiration', 0):
        return jsonify({'message': 'OTP has expired'}), 400
    
    # Hash the new password
    hashed_password = generate_password_hash(new_password)
    
    # Update the user's password in the database
    mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password, 'reset_otp': None, 'otp_expiration': None}})

    return jsonify({'message': 'Password has been reset successfully'}), 200


########  Google authentication   ####################



@bp.route('/google-login', methods=['GET'])
def google_login():
    # Redirect to Google's OAuth 2.0 server
    google_auth_endpoint = "https://accounts.google.com/o/oauth2/auth"
    redirect_uri = "http://127.0.0.1:5000/api/auth/google/callback"
    scope = "openid email profile"

    params = {
        "response_type": "code",
        "client_id": current_app.config["GOOGLE_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    # Build the URL for Google's OAuth 2.0 server
    auth_url = f"{google_auth_endpoint}?response_type={params['response_type']}&client_id={params['client_id']}&redirect_uri={params['redirect_uri']}&scope={params['scope']}"
    return jsonify({'auth_url': auth_url})


@bp.route('/google/callback', methods=['GET'])
def google_callback():
    # Get the authorization code from the request
    auth_code = request.args.get('code')

    if not auth_code:
        return jsonify({'message': 'Authorization code not provided'}), 400

    # Exchange the authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    redirect_uri = "http://127.0.0.1:5000/api/auth/google/callback"
    token_data = {
        "code": auth_code,
        "client_id": current_app.config["GOOGLE_CLIENT_ID"],
        "client_secret": current_app.config["GOOGLE_CLIENT_SECRET"],
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(token_url, data=token_data, headers=token_headers)

    if token_response.status_code != 200:
        return jsonify({'message': 'Failed to fetch token'}), 400

    token_json = token_response.json()
    id_token_str = token_json.get("id_token")

    # Verify the ID token
    try:
        id_info = id_token.verify_oauth2_token(id_token_str, google_requests.Request(), current_app.config["GOOGLE_CLIENT_ID"])

        # Extract user information
        email = id_info.get("email")
        full_name = id_info.get("name")

        # Check if the user exists in the database
        user = mongo.db.users.find_one({'email': email})
        if not user:
            # Create a new user if not found
            user = {
                "email": email,
                "full_name": full_name,
                "role": "user",
                "password": None,  # No password since it's Google Auth
            }
            mongo.db.users.insert_one(user)

        # Generate a JWT for the user
        token = jwt.encode({
            'user_id': str(user['_id']),
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=1),
        }, current_app.config['JWT_SECRET_KEY'])

        return jsonify({
            'token': token,
            'role': user['role'],
            'user_id': str(user['_id']),
        }), 200

    except ValueError as e:
        return jsonify({'message': 'Invalid token'}), 400
    



#########    Facebook authentication   ########################


@bp.route('/facebook-login', methods=['GET'])
def facebook_login():
    # Redirect to Facebook's OAuth 2.0 endpoint
    facebook_auth_endpoint = "https://www.facebook.com/v12.0/dialog/oauth"
    redirect_uri = current_app.config['FACEBOOK_REDIRECT_URI']
    client_id = current_app.config['FACEBOOK_APP_ID']

    # Build the Facebook login URL
    auth_url = (
        f"{facebook_auth_endpoint}?client_id={client_id}"
        f"&redirect_uri={redirect_uri}&state={{st=state123abc}}&scope=email,public_profile"
    )

    return jsonify({'auth_url': auth_url}), 200


@bp.route('/facebook/callback', methods=['GET'])
def facebook_callback():
    # Get the authorization code from the callback
    code = request.args.get('code')

    if not code:
        return jsonify({'message': 'Authorization code not provided'}), 400

    # Exchange the authorization code for an access token
    token_url = "https://graph.facebook.com/v12.0/oauth/access_token"
    client_id = current_app.config['FACEBOOK_APP_ID']
    client_secret = current_app.config['FACEBOOK_APP_SECRET']
    redirect_uri = current_app.config['FACEBOOK_REDIRECT_URI']

    token_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_secret": client_secret,
        "code": code
    }
    token_response = requests.get(token_url, params=token_params)
    token_data = token_response.json()

    if "access_token" not in token_data:
        return jsonify({'message': 'Failed to fetch access token'}), 400

    access_token = token_data['access_token']

    # Use the access token to fetch user info
    user_info_url = "https://graph.facebook.com/me"
    user_info_params = {
        "fields": "id,name,email",
        "access_token": access_token
    }
    user_info_response = requests.get(user_info_url, params=user_info_params)
    user_info = user_info_response.json()

    if "email" not in user_info:
        return jsonify({'message': 'Failed to fetch user information'}), 400

    # Extract user information
    email = user_info['email']
    full_name = user_info['name']

    # Check if the user exists in the database
    user = mongo.db.users.find_one({'email': email})
    if not user:
        # Create a new user if not found
        user = {
            "email": email,
            "full_name": full_name,
            "role": "user",
            "password": None,  # No password since it's Facebook Auth
        }
        mongo.db.users.insert_one(user)

    # Generate a JWT for the user
    token = jwt.encode({
        'user_id': str(user['_id']),
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=1),
    }, current_app.config['JWT_SECRET_KEY'])

    return jsonify({
        'token': token,
        'role': user['role'],
        'user_id': str(user['_id']),
    }), 200
