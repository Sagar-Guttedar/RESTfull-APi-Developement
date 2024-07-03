import token
import secrets
from flask import Flask, request, jsonify, session
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_bcrypt import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from hashlib import sha256
import base64

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)
mail = Mail(app)  # Initialize Flask-Mail
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["domainDB"]
users_collection = db["users"]


def generate_confirmation_token():
    # Generate a random string token for confirmation
    token_length = 32  # Length of the token
    token = secrets.token_hex(token_length)
    return token

def send_confirmation_email(username, token):
    confirmation_url = f"http://127.0.0.1:5000/confirm_email?token={token}"
    msg = Message('Confirm Your Email', recipients=[username])
    msg.body = f"Please click the following link to confirm your email: {confirmation_url}"
    mail.send(msg)

def hash_token(token):
    # Hash the token using SHA-256 for security
    hashed_token = sha256(token.encode()).hexdigest()
    return hashed_token

def encode_base64_token(token):
    # Encode token to Base64
    encoded_token = base64.b64encode(token.encode()).decode()
    return encoded_token


def decode_base64_token(encoded_token):
    # Decode Base64 token
    decoded_token = base64.b64decode(encoded_token).decode()
    return decoded_token


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Define the expected fields
    expected_fields = ['first_name', 'last_name', 'username', 'phone', 'city', 'addressid', 'password', 'user_type']

    # Check if all required fields are provided
    if not all(field in data for field in expected_fields):
        return jsonify({'error': 'All fields are required'}), 400

    # Extract the provided fields
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    username = data.get('username')
    phone = data.get('phone')
    city = data.get('city')
    address_id = data.get('addressid')
    password = data.get('password')
    user_type = data.get('user_type', 'normal')  # Default to 'normal' if user_type not provided

    # Check if the username or email already exists
    existing_user = users_collection.find_one({'$or': [{'username': username}]})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    # Generate password hash
    hashed_password = generate_password_hash(password).decode('utf-8')

    # Current date
    current_date = datetime.now()

    # Generate confirmation token
    confirmation_token = generate_confirmation_token()

    # Encode confirmation token to Base64
    encoded_token = encode_base64_token(confirmation_token)

    # Hash confirmation token for secure storage
    hashed_token = hash_token(confirmation_token)

    # Create user document with password, access_token, and confirmation token fields
    new_user = {
        'first_name': first_name,
        'last_name': last_name,
        'username': username,
        'phone': phone,
        'city': city,
        'addressid': address_id,
        'password': hashed_password,
        'access_token': None,
        'email_confirmation_token': hashed_token,  # Store hashed token
        'created_date': current_date,
        'updated_date': current_date,
        'user_status': 'inactive',  # Set user status to inactive initially
        'user_type': user_type
    }

    # Insert new user document into the database
    users_collection.insert_one(new_user)

    # Return the confirmation token along with the success message
    return jsonify({'message': 'User registered successfully.', 'username': username, 'email_confirmation_token': encoded_token}), 201


@app.route('/confirm_email', methods=['GET'])
def confirm_email():
    confirmation_token = request.args.get('token')
    if not confirmation_token:
        return jsonify({'error': 'Confirmation token is missing'}), 400
    
    # Decode Base64 encoded token
    decoded_token = decode_base64_token(confirmation_token)
    
    # Find the user with the provided confirmation token
    user = users_collection.find_one({'email_confirmation_token': hash_token(decoded_token)})
    if not user:
        return jsonify({'error': 'Invalid confirmation token'}), 400
    
    # Update user status to active
    users_collection.update_one({'_id': user['_id']}, {'$set': {'user_status': 'active'}})
    
    # Optionally, you can remove the confirmation token from the user document after confirmation
    # users_collection.update_one({'_id': user['_id']}, {'$unset': {'email_confirmation_token': ''}})
    
    return jsonify({'message': 'Email confirmed successfully.'}), 200


# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Find the user by email
    user = users_collection.find_one({'username': username})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Generate a new access token
    access_token = create_access_token(identity=username)

    # Get the user_id from the user document
    user_id = str(user.get('_id'))

    # Update the user document with the new access token
    users_collection.update_one({'username': username}, {'$set': {'access_token': access_token}})

    # Return the access_token and user_id in the response
    response = {'access_token': access_token, 'user_id': user_id}
    return jsonify(response), 200


# My Profile Endpoint
@app.route('/myprofile', methods=['GET'])
@jwt_required()
def my_profile():
    # Get the identity of the current user
    current_user = get_jwt_identity()

    # Find the user document in the database
    user = users_collection.find_one({'username': current_user}, {'_id': 0, 'password': 0, 'access_token': 0})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Return the user information
    return jsonify(user), 200


# Edit My Profile Endpoint
@app.route('/editmyprofile', methods=['PUT'])
@jwt_required()
def edit_my_profile():
    # Get the identity of the current user
    current_user = get_jwt_identity()

    # Get the updated profile data from the request
    data = request.get_json()

    # Set the updated_date to the current date and time
    data['updated_date'] = datetime.now()

    # Update the user document in the database
    result = users_collection.update_one({'username': current_user}, {'$set': data})

    if result.modified_count > 0:
        return jsonify({'message': 'Profile updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update profile'}), 500




# Forgot Password Endpoint
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    username = data.get('username')

    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a reset token
    reset_token = str(ObjectId())

    # Set expiration time for reset token (e.g., 1 hour from now)
    reset_exp_time = datetime.utcnow() + timedelta(hours=1)

    # Store reset token and its expiration time in the database
    users_collection.update_one({'_id': user['_id']}, {'$set': {'reset_token': reset_token, 'reset_exp_time': reset_exp_time}})

    # For simplicity, let's just return the reset token in the response
    return jsonify({'reset_token': reset_token}), 200



# Reset Password Endpoint
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    user = users_collection.find_one({'username': username, 'reset_token': reset_token, 'reset_exp_time': {'$gte': datetime.utcnow()}})
    if not user:
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    # Hash the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Update the user's password and remove reset token from the database
    users_collection.update_one({'_id': user['_id']}, {'$set': {'password': hashed_password}, '$unset': {'reset_token': '', 'reset_exp_time': ''}})

    return jsonify({'message': 'Password reset successfully'}), 200



#Logout Endpoint
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Here, you could handle the logout logic if necessary
    return jsonify({'message': 'Logged out successfully'}), 200



# Function to convert ObjectId to string in a user document
def convert_objectid_to_str(user):
    user['_id'] = str(user['_id'])
    return user

# List Users Endpoint with Pagination and Filtering
@app.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    # Get query parameters for pagination and filtering
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    city = request.args.get('city')
    user_type = request.args.get('user_type')

    # Build the query filter
    query = {}
    if city:
        query['city'] = city
    if user_type:
        try:
            user_type = int(user_type)
            query['user_type'] = user_type
        except ValueError:
            return jsonify({'error': 'user_type must be an integer'}), 400

    # Calculate the number of documents to skip
    skip = (page - 1) * limit

    # Fetch the users from the database with pagination and filtering
    users_cursor = users_collection.find(query).skip(skip).limit(limit)
    users = list(users_cursor)

    # Convert ObjectId to string in each user document
    users = [convert_objectid_to_str(user) for user in users]

    # Count total documents for pagination
    total_users = users_collection.count_documents(query)

    # Prepare the response with pagination information
    response = {
        'users': users,
        'total_users': total_users,
        'page': page,
        'limit': limit,
        'total_pages': (total_users + limit - 1) // limit  # Calculate total pages
    }

    return jsonify(response), 200

if __name__ == '__main__':
    app.run(debug=True)
