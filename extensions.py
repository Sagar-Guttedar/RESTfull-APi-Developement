from bson import ObjectId
from flask import request
from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity


app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['domainDB']
collection = db['extensions']
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
jwt = JWTManager(app)

@app.route('/extension', methods=['POST'])
@jwt_required()
def add_extension():
    data = request.json
    user_type = data['User_type']
    
    # Check if the user_type is 5 or 1
    if user_type not in [5]:
        return jsonify({'error': 'Unauthorized access.'}), 403
    
    if 'tlds' not in data:
        return jsonify({'error': 'TLDs is required'}), 400
    
    # Convert single TLD string to a list with one element
    tlds = [data['tlds']] if isinstance(data['tlds'], str) else data['tlds']
    
    # Check if the provided extension already exists in the database
    existing_extension = collection.find_one({'tlds': tlds})
    if existing_extension:
        return jsonify({'error': 'Extension already exists'}), 400
    
    # Check for spaces and multiple dots in each TLD
    for tld in tlds:
        if ' ' in tld:
            return jsonify({'error': 'Spaces are not allowed in TLDs'}), 400
        
    status = data.get('status', 'active')
    date = datetime.now()
    result = collection.insert_one({'tlds': tlds, 'status': status, 'date': date})
    return jsonify({'message': 'Extension added successfully', 'id': str(result.inserted_id)}), 201




@app.route('/extension/<extension_id>', methods=['PUT'])
@jwt_required()
def edit_extension(extension_id):
    data = request.json
    user_type = data['User_type']

    # Check if the user_type is 5 or 1
    if user_type not in [5]:
        return jsonify({'error': 'Unauthorized access.'}), 403

    # Check if the provided extension ID is valid
    if not ObjectId.is_valid(extension_id):
        return jsonify({'error': 'Invalid extension ID format'}), 400

    # Convert the string representation of ObjectId to ObjectId
    extension_id = ObjectId(extension_id)

    # Check if the extension with the provided ID exists
    existing_extension = collection.find_one({'_id': extension_id})
    if not existing_extension:
        return jsonify({'error': 'Extension not found'}), 404

    # Update the extension data
    update_data = {}
    if 'tlds' in data:
        tlds = data['tlds']

        # Check for spaces and multiple dots in each TLD
        for tld in tlds:
            if ' ' in tld:
                return jsonify({'error': 'Spaces are not allowed in TLDs'}), 400

        update_data['tlds'] = tlds

    if 'status' in data:
        update_data['status'] = data['status']

    # Update the extension data in the database
    result = collection.update_one({'_id': extension_id}, {'$set': update_data})

    if result.modified_count > 0:
        return jsonify({'message': 'Extension updated successfully'}), 200
    else:
        return jsonify({'message': 'Failed to update extension'}), 500


@app.route('/extension/<extension_id>', methods=['DELETE'])
@jwt_required()
def delete_extension(extension_id):
    data = request.json
    user_type = data['User_type']

    # Check if the user_type is 5 or 1
    if user_type not in [5]:
        return jsonify({'error': 'Unauthorized access.'}), 403

    # Check if the provided extension ID is valid
    if not ObjectId.is_valid(extension_id):
        return jsonify({'error': 'Invalid extension ID format'}), 400

    # Convert the string representation of ObjectId to ObjectId
    extension_id = ObjectId(extension_id)

    # Check if the extension with the provided ID exists
    existing_extension = collection.find_one({'_id': extension_id})
    if not existing_extension:
        return jsonify({'error': 'Extension not found'}), 404

    # Delete the extension from the database
    result = collection.delete_one({'_id': extension_id})

    if result.deleted_count > 0:
        return jsonify({'message': 'Extension deleted successfully'}), 200
    else:
        return jsonify({'message': 'Failed to delete extension'}), 500



if __name__ == '__main__':
    app.run(debug=True)
