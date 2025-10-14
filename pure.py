from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import secrets
import uuid
from functools import wraps
from pymongo import MongoClient
import os

app = Flask(__name__)

# Configuration
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY', 'solar')
MONGO_URI = os.getenv('MONGO_URI', "mongodb+srv://pure:tGqD6ciQ9E2nDacc@pureauth.8ykljss.mongodb.net/?retryWrites=true&w=majority&appName=Pureauth")

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client['pureauth']        # Database name
users_collection = db['users'] # Collection name

# ---------------- Admin & User Decorators ----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_key = request.headers.get('X-Admin-Key')
        if not admin_key or admin_key != ADMIN_SECRET_KEY:
            return jsonify({'error': 'Unauthorized. Invalid admin key.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        if token.startswith('Bearer '):
            token = token[7:]
        user = users_collection.find_one({'token': token})
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

# ---------------- Validation ----------------
import re
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    return len(password) >= 6

def validate_username(username):
    return len(username) >= 3 and username.isalnum()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token():
    return secrets.token_urlsafe(32)

# ---------------- Routes ----------------
@app.route('/')
def home():
    return jsonify({
        'message': 'PureAuth API',
        'version': '1.0.0',
        'endpoints': {
            'login': '/login',
            'register': '/register',
            'admin': {
                'list_users': '/admin/users',
                'get_user': '/admin/users/<user_id>',
                'add_user': '/admin/users',
                'delete_user': '/admin/users/<user_id>'
            }
        }
    })

# ---------------- User Routes ----------------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400
    if not validate_username(username):
        return jsonify({'error': 'Username must be at least 3 chars and alphanumeric'}), 400
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    if not validate_password(password):
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if users_collection.find_one({'$or':[{'username': username},{'email': email}]}):
        return jsonify({'error': 'Username or email already exists'}), 409

    user_id = str(uuid.uuid4())
    current_time = datetime.now().isoformat()

    new_user = {
        '_id': user_id,
        'username': username,
        'email': email,
        'password': hash_password(password),
        'created_at': current_time,
        'last_login': None,
        'token': None
    }

    users_collection.insert_one(new_user)

    return jsonify({'message': 'Registration successful', 'user': {
        'id': user_id, 'username': username, 'email': email, 'created_at': current_time
    }}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('email', '').strip()
    password = data.get('password', '')

    if not identifier or not password:
        return jsonify({'error': 'Email/username and password are required'}), 400

    user = users_collection.find_one({'$or':[{'username': identifier},{'email': identifier}]})
    if not user or user['password'] != hash_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token()
    users_collection.update_one({'_id': user['_id']}, {'$set': {'token': token, 'last_login': datetime.now().isoformat()}})

    return jsonify({'message': 'Login successful','token': token,'user': {
        'id': user['_id'],
        'username': user['username'],
        'email': user['email'],
        'created_at': user['created_at'],
        'last_login': datetime.now().isoformat()
    }}), 200

# ---------------- Admin Routes ----------------
@app.route('/admin/users', methods=['GET'])
@admin_required
def list_users():
    users = list(users_collection.find({}, {'password': 0, 'token': 0}))
    for u in users:
        u['id'] = u.pop('_id')
    return jsonify({'users': users, 'total': len(users)}), 200

@app.route('/admin/users/<user_id>', methods=['GET'])
@admin_required
def get_user(user_id):
    user = users_collection.find_one({'_id': user_id}, {'password':0,'token':0})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user['id'] = user.pop('_id')
    return jsonify({'user': user}), 200

@app.route('/admin/users', methods=['POST'])
@admin_required
def add_user():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password required'}), 400
    if not validate_username(username):
        return jsonify({'error': 'Username must be at least 3 chars and alphanumeric'}), 400
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    if not validate_password(password):
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if users_collection.find_one({'$or':[{'username': username},{'email': email}]}):
        return jsonify({'error': 'Username or email already exists'}), 409

    user_id = str(uuid.uuid4())
    current_time = datetime.now().isoformat()
    new_user = {
        '_id': user_id,
        'username': username,
        'email': email,
        'password': hash_password(password),
        'created_at': current_time,
        'last_login': None,
        'token': None
    }
    users_collection.insert_one(new_user)
    return jsonify({'message': 'User created successfully','user': {'id': user_id, 'username': username,'email': email,'created_at': current_time}}), 201

@app.route('/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    result = users_collection.delete_one({'_id': user_id})
    if result.deleted_count == 0:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': 'User deleted successfully', 'deleted_user_id': user_id}), 200

# ---------------- Error handlers ----------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ---------------- Run ----------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
