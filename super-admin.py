from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
from flask import abort
from bson import json_util
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from datetime import datetime
import traceback 

app = Flask(__name__)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
jwt = JWTManager(app)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["domainDB"]
users_collection = db["users"]


# Endpoint to add a new user
@app.route('/super-admin/user', methods=['POST'])
@jwt_required()
def add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone = data.get('phone')
    city = data.get('city')
    created_date = datetime.now()
    user_status = 'active'  # Assuming new users are active by default

    # Check if the user_type is 5 or user_type 1
    if user_type not in [5, 1]:
        return jsonify({'error': 'Please select either user type 5 or type 1'}), 403
    
    # Check if username and password are provided
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    existing_user = users_collection.find_one({'username': username})
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password)
    new_user = {
        'username': username,
        'password': hashed_password,
        'user_type': user_type,
        'first_name': first_name,
        'last_name': last_name,
        'phone': phone,
        'city': city,
        'created_date': created_date,
        'user_status': user_status
    }
    users_collection.insert_one(new_user)

    return jsonify({'message': 'User added successfully'}), 201




@app.route('/super-admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        users = list(users_collection.find())  
        # Convert ObjectId to string for _id field
        for user in users:
            user['_id'] = str(user['_id'])
            # Remove sensitive information like passwords before sending the response
            user.pop('password', None)
        return jsonify(users), 200
    except Exception as e:
        # Log the traceback for debugging
        traceback.print_exc()
        # Return a more detailed error response
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500


@app.route('/super-admin/user/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Convert ObjectId to string for _id field
        user['_id'] = str(user['_id'])
        
        # Remove sensitive information like password before sending the response
        user.pop('password', None)
        
        return jsonify(user), 200
    except Exception as e:
        # Log the traceback for debugging
        traceback.print_exc()
        # Return a more detailed error response
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500



@app.route('/super-admin/user/<string:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    data = request.get_json()
    # Check if all required fields are provided
    required_fields = ['first_name', 'last_name', 'username', 'phone', 'city', 'user_status', 'user_type']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'All required fields are not provided'}), 400
    
    # Set the updated_date automatically
    data['updated_date'] = datetime.now()

    # Update the user document in the database
    result = users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': data})
    
    if result.modified_count > 0:
        return jsonify({'message': 'User updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update user'}), 500



# Protected endpoint to delete a user
@app.route('/super-admin/user/<string:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    users_collection.delete_one({'_id': ObjectId(user_id)})
    return jsonify({'message': 'User deleted successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True)
