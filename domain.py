import re
from typing import OrderedDict
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from bson import ObjectId
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)  # 60 minutes
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['domainDB']
collection = db['domain']

@app.route('/domain', methods=['POST'])
@jwt_required()  
def add_new_domain():
    data = request.json
    user_type = data['User_type']
    
    if user_type not in [1, 3, 5]:
        return jsonify({'error': 'Unauthorized access.'}), 403
    
    current_username = get_jwt_identity()
    d_name = data['Domain_Name'] + "." + data['tlds']

    existing_domain = collection.find_one({'Domain_Name': d_name})
    if existing_domain:
        return jsonify({'error': 'Domain name already exists'}), 400

    if re.search(r'[^\w-]', data['Domain_Name']):
        return jsonify({'error': 'Special characters and dots are not allowed in domain name'}), 400

    domain_name_with_tld = f"{data['Domain_Name']}.{data['tlds']}"

    created_date = datetime.strptime(data['Created_Date'], '%Y-%m-%d')
    expiry_date = datetime.strptime(data['Expiry_Date'], '%Y-%m-%d')
    domain_age = (expiry_date - created_date).days

    domain_data = {
        'Domain_Name': domain_name_with_tld,
        'Description': data['Description'],
        'Status': data['Status'],
        'Created_Date': data['Created_Date'],
        'Expiry_Date': data['Expiry_Date'],
        'Domain_Age': domain_age,
        'Visits': data.get('Visits', 0),
        'ScreenShot': data.get('ScreenShot', ''),
        'Google_Page_Rank': data.get('Google_Page_Rank', ''),
        'Alexa_Rank': data.get('Alexa_Rank', ''),
        'Backlinks': data.get('Backlinks', 0),
        'User_type': data.get('User_type') or user_type,
    }

    result = collection.insert_one(domain_data)
    if result.inserted_id:
        response = {'message': 'Domain added successfully', 'domain_id': str(result.inserted_id)}
        return jsonify(response), 201
    else: 
        return jsonify({'message': 'Failed to add domain'}), 500


@app.route('/domain', methods=['DELETE'])
@jwt_required()  
def delete_domain():
    current_user = get_jwt_identity()

    data = request.json
    user_type = data.get('User_type')
    if user_type not in [1, 3, 5]:
        return jsonify({'error': 'Unauthorized access. '}), 403

    domain_id = data.get('domain_id')
    if not domain_id:
        return jsonify({'error': 'Domain ID is required'}), 400

    if not ObjectId.is_valid(domain_id):
        return jsonify({'error': 'Invalid domain ID format'}), 400

    domain_id = ObjectId(domain_id)
    existing_domain = collection.find_one({'_id': domain_id})
    if not existing_domain:
        return jsonify({'error': 'Domain not found'}), 404

    delete_result = collection.delete_one({'_id': domain_id})
    if delete_result.deleted_count > 0:
        return jsonify({'message': 'Domain deleted successfully'}), 200
    else:
        return jsonify({'message': 'Failed to delete domain'}), 500


@app.route('/domain', methods=['PUT'])
@jwt_required()  
def edit_domain():
    data = request.json
    user_type = data['User_type']
    
    if user_type not in [1, 3, 5]:
        return jsonify({'error': 'Unauthorized user.'}), 403
    
    domain_id = data.get('domain_id')
    if not domain_id:
        return jsonify({'error': 'Domain ID is required'}), 400

    if not ObjectId.is_valid(domain_id):
        return jsonify({'error': 'Invalid domain ID format'}), 400

    domain_id = ObjectId(domain_id)
    existing_domain = collection.find_one({'_id': domain_id})
    if not existing_domain:
        return jsonify({'error': 'Domain not found'}), 404

    data.pop('domain_id', None)

    update_result = collection.update_one({'_id': domain_id}, {'$set': data})
    if update_result.modified_count > 0:
        return jsonify({'message': 'Domain updated successfully'}), 200
    else:
        return jsonify({'message': 'Failed to update domain'}), 500

def convert_objectid_to_str(domain):
    domain['_id'] = str(domain['_id'])
    return domain


@app.route('/domains', methods=['GET'])
@jwt_required()  
def list_domains():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    filters = {}

    domain_name = request.args.get('Domain_Name')
    if domain_name:
        filters['Domain_Name'] = {'$regex': domain_name, '$options': 'i'} 

    user_type = request.args.get('User_type')
    if user_type:
        try:
            user_type = int(user_type)
            filters['User_type'] = user_type
        except ValueError:
            return jsonify({'error': 'User_type must be an integer'}), 400

    skip = (page - 1) * limit
    domains_cursor = collection.find(filters).skip(skip).limit(limit)
    domains = list(domains_cursor)

    domains = [convert_objectid_to_str(domain) for domain in domains]
    total_domains = collection.count_documents(filters)

    response = {
        'domains': domains,
        'total_domains': total_domains,
        'page': page,
        'limit': limit,
        'total_pages': (total_domains + limit - 1) // limit  
    }

    return jsonify(response), 200


if __name__ == '__main__':
    app.run(debug=True)
