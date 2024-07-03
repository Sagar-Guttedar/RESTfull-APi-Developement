from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configure MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['domainDB']  
services_collection = db['services']

# Set up JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
jwt = JWTManager(app)

# Add a new service
@app.route('/services', methods=['POST'])
@jwt_required()
def add_service():
    data = request.get_json()
    service = {
        'service_name': data['service_name'],
        'service_status': data['service_status'],
        'service_created': data['service_created']
    }
    result = services_collection.insert_one(service)
    
    if result.inserted_id:
        return jsonify({'message': 'Service added successfully', 'id': str(result.inserted_id)}), 201
    else:
        return jsonify({'error': 'Failed to add service'}), 500
    

# Update a service
@app.route('/services/<service_id>', methods=['PUT'])
@jwt_required()
def update_service(service_id):
    data = request.get_json()
    update_data = {
        'service_name': data.get('service_name'),
        'service_status': data.get('service_status'),
        'service_created': data.get('service_created')
    }
    result = services_collection.update_one({'_id': ObjectId(service_id)}, {'$set': update_data})
    if result.matched_count:
        return jsonify({'message': 'Service updated successfully'})
    else:
        return jsonify({'error': 'Service not found'}), 404


# Get a specific service
@app.route('/services/<service_id>', methods=['GET'])
@jwt_required()
def get_service(service_id):
    service = services_collection.find_one({'_id': ObjectId(service_id)})
    if service:
        service['_id'] = str(service['_id'])
        return jsonify(service)
    else:
        return jsonify({'error': 'Service not found'}), 404

# Get all services
@app.route('/services', methods=['GET'])
@jwt_required()
def get_all_services():
    services = list(services_collection.find())
    for service in services:
        service['_id'] = str(service['_id'])
    return jsonify(services)


# Delete a service
@app.route('/services/<service_id>', methods=['DELETE'])
@jwt_required()
def delete_service(service_id):
    result = services_collection.delete_one({'_id': ObjectId(service_id)})
    if result.deleted_count:
        return jsonify({'message': 'Service deleted successfully'})
    else:
        return jsonify({'error': 'Service not found'}), 404


if __name__ == '__main__':
    app.run(debug=True)
