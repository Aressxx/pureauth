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
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY', 'solar')
MONGO_URI = os.getenv('MONGO_URI', "mongodb+srv://pureauth:Ld5jRvoi5btcdrZl@pureauth.8ykljss.mongodb.net/pureauth?retryWrites=true&w=majority")
## Crypto configs removed

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client['pureauth']        # Database name
    users_collection = db['users'] # Collection name
    settings_collection = db['settings'] # Global settings
    premium_keys_collection = db['premium_keys'] # Premium signup keys
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")
    client = None
    db = None
    users_collection = None
    settings_collection = None
    premium_keys_collection = None

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
        premium_key = data.get('premium_key', '').strip()

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

        plan = 'free'
        databases = []
        if premium_key and premium_keys_collection is not None:
            key_doc = premium_keys_collection.find_one({'key': premium_key, 'used_by': None})
            if key_doc:
                plan = 'premium'
                premium_keys_collection.update_one({'_id': key_doc['_id']}, {'$set': {'used_by': user_id, 'used_at': current_time}})
            else:
                return jsonify({'error': 'Invalid or already used premium key'}), 400

        new_user = {
            '_id': user_id,
            'username': username,
            'email': email,
            'password': hash_password(password),
            'created_at': current_time,
            'last_login': None,
            'token': None,
            'is_active': True,
            'plan': plan,
            'databases': databases
        }

        users_collection.insert_one(new_user)

        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': current_time,
                'plan': plan
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

        plan = data.get('plan', 'free')
        if plan not in ['free', 'premium']:
            plan = 'free'
        new_user = {
            '_id': user_id,
            'username': username,
            'email': email,
            'password': hash_password(password),
            'created_at': current_time,
            'last_login': None,
            'token': None,
            'is_active': True,
            'plan': plan,
            'databases': []
        }

        users_collection.insert_one(new_user)

        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': current_time,
                'plan': plan
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

# ---------------- Settings & Premium ----------------
@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    try:
        if request.method == 'GET':
            doc = settings_collection.find_one({'_id': 'global'}) or {}
            if doc:
                doc['id'] = doc.pop('_id')
            return jsonify({'settings': doc}), 200
        data = request.get_json() or {}
        announcement = data.get('announcement', '')
        version = data.get('version', '')
        settings_collection.update_one({'_id': 'global'}, {'$set': {'announcement': announcement, 'version': version}}, upsert=True)
        return jsonify({'message': 'Settings updated', 'settings': {'id': 'global', 'announcement': announcement, 'version': version}}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to process settings', 'details': str(e)}), 500

def _format_premium_key():
    # pure-xxxx-xxxx (alnum lowercase)
    import random, string
    def seg():
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"pure-{seg()}-{seg()}"

@app.route('/admin/premium-keys', methods=['GET', 'POST'])
@admin_required
def premium_keys():
    try:
        if request.method == 'GET':
            keys = []
            for k in premium_keys_collection.find({}):
                used_by = k.get('used_by')
                used_by_user = None
                if used_by:
                    u = users_collection.find_one({'_id': used_by}, {'username': 1, 'email': 1})
                    if u:
                        used_by_user = {'id': used_by, 'username': u.get('username'), 'email': u.get('email')}
                keys.append({
                    'key': k.get('key'),
                    'created_at': k.get('created_at'),
                    'used_by': used_by_user,
                    'used_at': k.get('used_at')
                })
            return jsonify({'keys': keys}), 200
        data = request.get_json() or {}
        key = data.get('key') or _format_premium_key()
        premium_keys_collection.insert_one({'key': key, 'created_at': datetime.now().isoformat(), 'used_by': None, 'used_at': None})
        return jsonify({'message': 'Key created', 'key': key}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to process premium keys', 'details': str(e)}), 500

@app.route('/admin/premium-keys/<key>', methods=['DELETE'])
@admin_required
def delete_premium_key(key):
    try:
        res = premium_keys_collection.delete_one({'key': key})
        if res.deleted_count == 0:
            return jsonify({'error': 'Key not found'}), 404
        return jsonify({'message': 'Key deleted'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to delete key', 'details': str(e)}), 500

# User database management (per-plan limits)
def get_user_plan_limits(user_doc):
    if user_doc.get('plan') == 'premium':
        return {'max_databases': 4}
    return {'max_databases': 1}

@app.route('/user/databases', methods=['GET', 'POST'])
@token_required
def user_databases():
    try:
        user = request.current_user
        if request.method == 'GET':
            return jsonify({'databases': user.get('databases', [])}), 200
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        uri = data.get('connectionUri', '').strip()
        if not name or not uri:
            return jsonify({'error': 'name and connectionUri are required'}), 400
        limits = get_user_plan_limits(user)
        current = user.get('databases', [])
        if len(current) >= limits['max_databases']:
            return jsonify({'error': 'Database limit reached for your plan'}), 403
        new_list = current + [{'name': name, 'connectionUri': uri}]
        users_collection.update_one({'_id': user['_id']}, {'$set': {'databases': new_list}})
        return jsonify({'message': 'Database added', 'databases': new_list}), 201
    except Exception as e:
        return jsonify({'error': 'Failed to process databases', 'details': str(e)}), 500

@app.route('/user/databases/<name>', methods=['DELETE'])
@token_required
def delete_user_database(name):
    try:
        user = request.current_user
        current = user.get('databases', [])
        new_list = [d for d in current if d.get('name') != name]
        users_collection.update_one({'_id': user['_id']}, {'$set': {'databases': new_list}})
        return jsonify({'message': 'Database removed', 'databases': new_list}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to remove database', 'details': str(e)}), 500

@app.route('/admin/premium-users', methods=['GET'])
@admin_required
def premium_users_summary():
    try:
        users = list(users_collection.find({'plan': 'premium'}, {'password': 0, 'token': 0}))
        result = []
        for u in users:
            dbs = u.get('databases', []) or []
            result.append({
                'id': u.get('_id'),
                'username': u.get('username'),
                'email': u.get('email'),
                'databases_count': len(dbs),
                'databases': [{
                    'name': d.get('name'),
                    'users_count': d.get('usersCount') if isinstance(d.get('usersCount'), int) else None
                } for d in dbs]
            })
        return jsonify({'premium_users': result}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to fetch premium users', 'details': str(e)}), 500

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

# (Crypto endpoints removed by request)

# ---------------- Run ----------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
