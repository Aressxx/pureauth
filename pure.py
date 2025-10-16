from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import secrets
import uuid
from functools import wraps
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from flask_cors import CORS
import requests
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY', 'solar')
MONGO_URI = os.getenv('MONGO_URI', "mongodb+srv://pureauth:Ld5jRvoi5btcdrZl@pureauth.8ykljss.mongodb.net/pureauth?retryWrites=true&w=majority")
CMC_API_KEY = os.getenv('CMC_API_KEY', '1c9d7ce683bb46cebe8707898d0f5a0b')
ETHERSCAN_API_KEY = os.getenv('9MSIEZMPHGWB35KKFFW5Y8MWJSS38EN2CN', '')
SOLSCAN_API_KEY = os.getenv('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjcmVhdGVkQXQiOjE3NjA2MTU3MTg2MzIsImVtYWlsIjoiZmVtaXcxMzA0M0BlbHlnaWZ0cy5jb20iLCJhY3Rpb24iOiJ0b2tlbi1hcGkiLCJhcGlWZXJzaW9uIjoidjIiLCJpYXQiOjE3NjA2MTU3MTh9.GWZnfAqGlPoClFHTqdeNPYUqpA2cXJOZl08ofUzcoew', '')

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client['pureauth']        # Database name
    users_collection = db['users'] # Collection name
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None
    users_collection = None

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
        'status': 'active',
        'endpoints': {
            'login': '/login',
            'register': '/register',
            'admin': {
                'list_users': '/admin/users',
                'get_user': '/admin/users/<user_id>',
                'add_user': '/admin/users',
                'delete_user': '/admin/users/<user_id>'
            }
        },
        'admin_key_required': 'X-Admin-Key header for admin endpoints'
    })

# ---------------- User Routes ----------------
@app.route('/register', methods=['POST'])
def register():
    try:
        if users_collection is None:
            return jsonify({'error': 'Database connection not available'}), 500

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')

        # Validation
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        if not validate_username(username):
            return jsonify({'error': 'Username must be at least 3 characters and alphanumeric'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        existing_user = users_collection.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
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
            'token': None,
            'is_active': True
        }

        users_collection.insert_one(new_user)

        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': current_time
            }
        }), 201

    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        if users_collection is None:
            return jsonify({'error': 'Database connection not available'}), 500

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400

        identifier = data.get('email', '').strip()
        password = data.get('password', '')

        if not identifier or not password:
            return jsonify({'error': 'Email/username and password are required'}), 400

        user = users_collection.find_one({
            '$or': [
                {'username': identifier},
                {'email': identifier}
            ]
        })

        if not user or user['password'] != hash_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.get('is_active', True):
            return jsonify({'error': 'Account is deactivated'}), 401

        token = generate_token()
        current_time = datetime.now().isoformat()

        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {
                'token': token,
                'last_login': current_time
            }}
        )

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['_id'],
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at'],
                'last_login': current_time
            }
        }), 200

    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# ---------------- Admin Routes ----------------
@app.route('/admin/users', methods=['GET'])
@admin_required
def list_users():
    try:
        users = list(users_collection.find({}, {'password': 0, 'token': 0}))
        for user in users:
            user['id'] = user.pop('_id')
        return jsonify({
            'users': users,
            'total': len(users),
            'message': 'Users retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/admin/users/<user_id>', methods=['GET'])
@admin_required
def get_user(user_id):
    try:
        user = users_collection.find_one({'_id': user_id}, {'password': 0, 'token': 0})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        user['id'] = user.pop('_id')
        return jsonify({
            'user': user,
            'message': 'User retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/admin/users', methods=['POST'])
@admin_required
def add_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        if not validate_username(username):
            return jsonify({'error': 'Username must be at least 3 characters and alphanumeric'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        existing_user = users_collection.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
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
            'token': None,
            'is_active': True
        }

        users_collection.insert_one(new_user)

        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': current_time
            }
        }), 201

    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@app.route('/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        result = users_collection.delete_one({'_id': user_id})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'message': 'User deleted successfully',
            'deleted_user_id': user_id
        }), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

# ---------------- Health Check ----------------
@app.route('/health')
def health_check():
    try:
        client.admin.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

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

# ---------------- Crypto Endpoints ----------------
@app.route('/crypto/listings', methods=['GET'])
@token_required
def crypto_listings():
    try:
        limit = int(request.args.get('limit', '50'))
        limit = max(1, min(limit, 100))
        if not CMC_API_KEY:
            return jsonify({'error': 'CMC API key not configured'}), 500
        headers = {
            'Accepts': 'application/json',
            'X-CMC_PRO_API_KEY': CMC_API_KEY
        }
        params = {
            'start': '1',
            'limit': str(limit),
            'convert': 'USD'
        }
        resp = requests.get('https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest', headers=headers, params=params, timeout=15)
        data = resp.json()
        return jsonify(data), resp.status_code
    except Exception as e:
        return jsonify({'error': 'Failed to fetch listings', 'details': str(e)}), 500


@app.route('/crypto/balance/btc/<address>', methods=['GET'])
@token_required
def btc_balance(address):
    try:
        # Use blockchain.info free endpoint
        resp = requests.get(f'https://blockchain.info/balance?active={address}', timeout=15)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch BTC balance'}), resp.status_code
        j = resp.json() or {}
        entry = j.get(address) or {}
        balance_satoshi = entry.get('final_balance', 0)
        return jsonify({
            'address': address,
            'balance': float(balance_satoshi) / 1e8,
            'unit': 'BTC',
            'raw': j
        })
    except Exception as e:
        return jsonify({'error': 'Failed to fetch BTC balance', 'details': str(e)}), 500


@app.route('/crypto/balance/eth/<address>', methods=['GET'])
@token_required
def eth_balance(address):
    try:
        if not ETHERSCAN_API_KEY:
            return jsonify({'error': 'ETHERSCAN_API_KEY not configured'}), 500
        params = {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest',
            'apikey': ETHERSCAN_API_KEY
        }
        resp = requests.get('https://api.etherscan.io/api', params=params, timeout=15)
        j = resp.json()
        if j.get('status') == '0':
            return jsonify({'error': j.get('message', 'Failed to fetch ETH balance'), 'details': j.get('result')}), 400
        wei = int(j.get('result', '0'))
        return jsonify({
            'address': address,
            'balance': wei / 1e18,
            'unit': 'ETH',
            'raw': j
        })
    except Exception as e:
        return jsonify({'error': 'Failed to fetch ETH balance', 'details': str(e)}), 500


@app.route('/crypto/balance/sol/<address>', methods=['GET'])
@token_required
def sol_balance(address):
    try:
        # Solscan public API v2
        headers = {}
        if SOLSCAN_API_KEY:
            headers['token'] = SOLSCAN_API_KEY
        resp = requests.get(f'https://public-api.solscan.io/account/{address}', headers=headers, timeout=15)
        if resp.status_code != 200:
            return jsonify({'error': 'Failed to fetch SOL balance'}), resp.status_code
        j = resp.json()
        lamports = j.get('lamports', 0)
        return jsonify({
            'address': address,
            'balance': float(lamports) / 1e9,
            'unit': 'SOL',
            'raw': j
        })
    except Exception as e:
        return jsonify({'error': 'Failed to fetch SOL balance', 'details': str(e)}), 500

# ---------------- Run ----------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
