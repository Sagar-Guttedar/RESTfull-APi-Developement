import re
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required, create_access_token
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
jwt = JWTManager(app)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["domainDB"]
users_collection = db["superUsers"]


# Super admin registration endpoint
@app.route('/superadmin/register', methods=['POST'])
def superadmin_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if username and password are provided
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Check if the username already exists
    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    # Hash the password
    hashed_password = generate_password_hash(password)
    
    # Add the user to the database with usertype 5 and user_type_name "superadmin"
    new_user = {
        'username': username,
        'password': hashed_password,
        'user_type': 5
    }
    users_collection.insert_one(new_user)

    return jsonify({'message': 'Super admin registered successfully'}), 201


# Super admin login endpoint
@app.route('/superadmin/login', methods=['POST'])
def superadmin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    superadmin = users_collection.find_one({'username': username})  # Check for user_type 5

    if superadmin and check_password_hash(superadmin['password'], password):
        # Generate access token
        token = create_access_token(identity=str(superadmin['_id']), expires_delta=datetime.timedelta(minutes=60))
        
        # Update access token in the user document
        users_collection.update_one({'_id': superadmin['_id']}, {'$set': {'access_token': token}})
        
        # Set user_id, user_type, and access_token in the response
        response = {
            'user_id': str(superadmin['_id']),
            'user_type': 5,
            'access_token': token
        }
        
        return jsonify(response), 200
    else:  
        return jsonify({'error': 'Invalid username or password'}), 401



# Logout Endpoint
@app.route('/logout', methods=['POST'])
@jwt_required()  # Requires a valid JWT token
def logout():
    current_user = get_jwt_identity()

    # Remove access token from user document
    users_collection.update_one({'username': current_user}, {'$unset': {'access_token': ''}})

    return jsonify({'message': 'Logout successful'}), 200



if __name__ == '__main__':
    app.run(debug=True)
