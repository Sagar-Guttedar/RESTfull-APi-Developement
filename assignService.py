from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configure MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['domainDB']
assign_service_collection = db['assignService']

# Set up JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
jwt = JWTManager(app)

# Add a new assignment
@app.route('/assignService', methods=['POST'])
@jwt_required()
def add_assign_service():
    data = request.get_json()
    assign_id = ObjectId()
    assign_service = {
        '_id': assign_id,
        'service_id': data['service_id'],
        'user_id': data['user_id'],
        'transaction_id': data['transaction_id']
    }
    result = assign_service_collection.insert_one(assign_service)
    return jsonify({'message': 'Service assigned successfully', 'id': str(result.inserted_id)}), 201


# Get all assignments
@app.route('/assignService', methods=['GET'])
@jwt_required()
def get_assign_services():
    assign_services = list(assign_service_collection.find())
    for assign_service in assign_services:
        assign_service['_id'] = str(assign_service['_id'])
    return jsonify(assign_services)

# Get a specific assignment
@app.route('/assignService/<assign_id>', methods=['GET'])
@jwt_required()
def get_assign_service(assign_id):
    assign_service = assign_service_collection.find_one({'_id': ObjectId(assign_id)})
    if assign_service:
        assign_service['_id'] = str(assign_service['_id'])
        return jsonify(assign_service)
    else:
        return jsonify({'error': 'Assign service not found'}), 404

# Update an assignment
@app.route('/assignService/<assign_id>', methods=['PUT'])
@jwt_required()
def update_assign_service(assign_id):
    data = request.get_json()
    update_data = {
        'service_id': data.get('service_id'),
        'user_id': data.get('user_id'),
        'transaction_id': data.get('transaction_id')
    }
    update_data = {k: v for k, v in update_data.items() if v is not None}
    result = assign_service_collection.update_one({'_id': ObjectId(assign_id)}, {'$set': update_data})
    if result.matched_count:
        return jsonify({'message': 'service updated successfully'})
    else:
        return jsonify({'error': 'service not found'}), 404

# Delete an assignment
@app.route('/assignService/<assign_id>', methods=['DELETE'])
@jwt_required()
def delete_assign_service(assign_id):
    result = assign_service_collection.delete_one({'_id': ObjectId(assign_id)})
    if result.deleted_count:
        return jsonify({'message': 'Service deleted successfully'})
    else:
        return jsonify({'error': 'Service not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
