from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["domainDB"]
user_types_collection = db["userType"]

# Create User Type API
@app.route('/user-type', methods=['POST'])
def create_user_type():
    data = request.get_json()
    user_type_name = data.get('user_type_name')
    user_type = data.get('user_type')
    status = data.get('status')
    created_at = datetime.now()

    # Check if user_type is an integer
    if not isinstance(user_type, int):
        return jsonify({'error': 'User type should be an integer'}), 400

    if user_type == 5:
        return jsonify({'error': ' User type is invalid '}), 400

    if not user_type_name or not status:
        return jsonify({'error': 'User type name and status are required fields'}), 400

    new_user_type = {
        'user_type_name': user_type_name,
        'user_type': user_type,
        'status': status,
        'created_at': created_at
    }

    user_type_id = user_types_collection.insert_one(new_user_type).inserted_id

    return jsonify({'message': 'UserType created successfully', 'user_type_id': str(user_type_id)}), 201

if __name__ == '__main__':
    app.run(debug=True)
