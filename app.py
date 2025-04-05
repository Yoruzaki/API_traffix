from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import DictCursor
import jwt
import datetime
from functools import wraps
from werkzeug.utils import secure_filename
import os
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# PostgreSQL configuration using Render's connection string
DATABASE_URL = "postgresql://traffix_lg5f_user:ebJu1mTba1sem66WC9dyPJg8VlHgcZnU@dpg-cvknp82dbo4c73f962r0-a.oregon-postgres.render.com/traffix_lg5f"

# Parse the database URL
result = urlparse(DATABASE_URL)
username = result.username
password = result.password
database = result.path[1:]
hostname = result.hostname

app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def get_db_connection():
    conn = psycopg2.connect(
        database=database,
        user=username,
        password=password,
        host=hostname,
        cursor_factory=DictCursor
    )
    return conn

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = get_user_by_id(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['name', 'email', 'phone', 'password', 'cin', 'license_plate', 'vehicle_type']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'{field} is required!'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
        if cur.fetchone():
            return jsonify({'message': 'Email already exists!'}), 400
        
        # Store plain text password (in production, use hashing)
        hashed_password = data['password']
        
        cur.execute("""
            INSERT INTO users 
            (name, email, phone, password_hash, role, license_plate, vehicle_type, cin) 
            VALUES (%s, %s, %s, %s, 'civil', %s, %s, %s)
            RETURNING id
        """, (
            data['name'],
            data['email'],
            data['phone'],
            hashed_password,
            data['license_plate'],
            data['vehicle_type'],
            data['cin']
        ))
        user_id = cur.fetchone()['id']
        conn.commit()
        
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({'token': token, 'user_id': user_id}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'identifier' not in data or 'password' not in data:
        return jsonify({'message': 'Identifier and password are required!'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT * FROM users WHERE email = %s OR badge_number = %s", 
                   (data['identifier'], data['identifier']))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        # Compare plain text passwords (in production, use hashing)
        if data['password'] != user['password_hash']:
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        user_dict = dict(user)
        user_dict.pop('password_hash', None)
        
        return jsonify({'token': token, 'user': user_dict})
    finally:
        cur.close()
        conn.close()

@app.route('/api/user', methods=['GET'])
@token_required
def get_current_user(current_user):
    user_dict = dict(current_user)
    user_dict.pop('password_hash', None)
    return jsonify(user_dict)

@app.route('/api/violations', methods=['GET'])
@token_required
def get_violations(current_user):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        if current_user['role'] == 'police':
            cur.execute("""
                SELECT v.*, u.name as officer_name 
                FROM violations v
                LEFT JOIN users u ON v.officer_id = u.id
                ORDER BY v.violation_date DESC
            """)
        else:
            cur.execute("""
                SELECT v.*, u.name as officer_name 
                FROM violations v
                LEFT JOIN users u ON v.officer_id = u.id
                WHERE v.license_plate = %s
                ORDER BY v.violation_date DESC
            """, (current_user['license_plate'],))
        
        violations = cur.fetchall()
        return jsonify(violations)
    finally:
        cur.close()
        conn.close()

@app.route('/api/violations', methods=['POST'])
@token_required
def create_violation(current_user):
    if current_user['role'] != 'police':
        return jsonify({'message': 'Only police officers can create violations!'}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['license_plate', 'violation_type', 'location', 
                         'violation_date', 'fine_amount', 'insurance_policy']
        
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        license_plate = data['license_plate'].strip().upper()
        violation_type = data['violation_type']
        location = data['location']
        notes = data.get('notes', '')
        violation_date = data['violation_date']
        fine_amount = float(data['fine_amount'])
        insurance_policy = data['insurance_policy']
        
        # Get vehicle owner info if exists
        cur.execute("""
            SELECT id, name FROM users 
            WHERE license_plate = %s AND role = 'civil'
        """, (license_plate,))
        owner = cur.fetchone()
        
        owner_id = owner['id'] if owner else None
        owner_name = owner['name'] if owner else 'Unknown'
        
        # Create violation
        cur.execute("""
            INSERT INTO violations 
            (license_plate, owner_name, insurance_policy, violation_type, 
             violation_date, location, fine_amount, notes, officer_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            license_plate,
            owner_name,
            insurance_policy,
            violation_type,
            violation_date,
            location,
            fine_amount,
            notes,
            current_user['id']
        ))
        violation_id = cur.fetchone()['id']
        
        # Create notification if owner exists
        if owner:
            cur.execute("""
                INSERT INTO notifications 
                (user_id, title, message)
                VALUES (%s, 'New Violation', %s)
            """, (
                owner['id'],
                f"New {violation_type} violation recorded for your vehicle {license_plate}. Fine: {fine_amount} DZD"
            ))
        
        conn.commit()
        return jsonify({
            'message': 'Violation created successfully!', 
            'violation_id': violation_id
        }), 201
        
    except ValueError as e:
        return jsonify({'message': 'Invalid fine amount format'}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/violations/<int:violation_id>/pay', methods=['PUT', 'OPTIONS'])
@token_required
def pay_violation(current_user, violation_id):
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. First verify the violation exists
        cur.execute("SELECT id, license_plate FROM violations WHERE id = %s", (violation_id,))
        violation = cur.fetchone()
        
        if not violation:
            return jsonify({'error': 'Violation not found'}), 404
        
        # 2. Verify the violation belongs to the current user
        if violation['license_plate'] != current_user['license_plate']:
            return jsonify({
                'error': 'Violation does not belong to user',
                'user_plate': current_user['license_plate'],
                'violation_plate': violation['license_plate']
            }), 403
        
        # 3. Attempt payment
        cur.execute("""
            UPDATE violations 
            SET paid = TRUE, payment_date = NOW() 
            WHERE id = %s
            RETURNING id, paid, payment_date
        """, (violation_id,))
        
        updated_violation = cur.fetchone()
        
        # 4. Create notification
        cur.execute("""
            INSERT INTO notifications 
            (user_id, title, message, created_at)
            VALUES (%s, %s, %s, NOW())
            RETURNING id
        """, (
            current_user['id'],
            'Payment Confirmed',
            f'Payment received for violation #{violation_id}'
        ))
        
        conn.commit()
        
        return jsonify({
            'message': 'Payment successful',
            'violation_id': violation_id,
            'paid_status': updated_violation['paid'],
            'payment_date': updated_violation['payment_date']
        })
        
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({
            'error': 'Database operation failed',
            'details': str(e),
            'violation_id': violation_id,
            'user_id': current_user.get('id'),
            'user_plate': current_user.get('license_plate')
        }), 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT * FROM notifications 
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (current_user['id'],))
        notifications = cur.fetchall()
        
        # Mark as read when fetched
        cur.execute("""
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE user_id = %s AND is_read = FALSE
        """, (current_user['id'],))
        conn.commit()
        
        return jsonify(notifications)
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@token_required
def delete_notification(current_user, notification_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            DELETE FROM notifications 
            WHERE id = %s AND user_id = %s
        """, (notification_id, current_user['id']))
        conn.commit()
        return jsonify({'message': 'Notification deleted successfully!'})
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
