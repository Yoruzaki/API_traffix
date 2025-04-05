import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import DictCursor
import jwt
import datetime
from functools import wraps
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://traffix_lg5f_user:ebJu1mTba1sem66WC9dyPJg8VlHgcZnU@dpg-cvknp22bo4c73f962r0-a/traffix_lg5f')

# Parse the database URL
result = urlparse(DATABASE_URL)
username = result.username
password = result.password
database = result.path[1:]
hostname = result.hostname
port = result.port

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

def get_db_connection():
    conn = psycopg2.connect(
        database=database,
        user=username,
        password=password,
        host=hostname,
        port=port
    )
    return conn

# Helper functions
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
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

# Auth Routes
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
        # Check if email exists
        cur.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
        if cur.fetchone():
            return jsonify({'message': 'Email already exists!'}), 400
        
        # Insert new user (in production, hash the password)
        cur.execute("""
            INSERT INTO users 
            (name, email, phone, password_hash, role, license_plate, vehicle_type, cin) 
            VALUES (%s, %s, %s, %s, 'civil', %s, %s, %s)
            RETURNING id
        """, (
            data['name'],
            data['email'],
            data['phone'],
            data['password'],  # In production: generate_password_hash(data['password'])
            data['license_plate'],
            data['vehicle_type'],
            data['cin']
        ))
        
        user_id = cur.fetchone()[0]
        conn.commit()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'token': token,
            'user_id': user_id,
            'message': 'User registered successfully'
        }), 201
        
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
    cur = conn.cursor(cursor_factory=DictCursor)
    
    try:
        cur.execute("""
            SELECT * FROM users 
            WHERE email = %s OR badge_number = %s
        """, (data['identifier'], data['identifier']))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        # In production: check_password_hash(user['password_hash'], data['password'])
        if data['password'] != user['password_hash']:
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        # Generate token
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        # Remove password before returning
        user.pop('password_hash')
        
        return jsonify({
            'token': token,
            'user': user,
            'message': 'Login successful'
        })
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# User Routes
@app.route('/api/user', methods=['GET'])
@token_required
def get_current_user(current_user):
    current_user.pop('password_hash', None)
    return jsonify(current_user)

# Violation Routes
@app.route('/api/violations', methods=['GET'])
@token_required
def get_violations(current_user):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
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
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/violations', methods=['POST'])
@token_required
def create_violation(current_user):
    if current_user['role'] != 'police':
        return jsonify({'message': 'Only police officers can create violations!'}), 403
    
    data = request.get_json()
    required_fields = ['license_plate', 'violation_type', 'location', 'violation_date', 'fine_amount']
    
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'message': f'Missing fields: {", ".join(missing_fields)}'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get vehicle owner info if exists
        cur.execute("""
            SELECT id, name FROM users 
            WHERE license_plate = %s AND role = 'civil'
        """, (data['license_plate'].upper(),))
        owner = cur.fetchone()
        
        # Create violation
        cur.execute("""
            INSERT INTO violations 
            (license_plate, owner_name, violation_type, violation_date, 
             location, fine_amount, notes, officer_id, insurance_policy)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data['license_plate'].upper(),
            owner['name'] if owner else 'Unknown',
            data['violation_type'],
            data['violation_date'],
            data['location'],
            float(data['fine_amount']),
            data.get('notes', ''),
            current_user['id'],
            data.get('insurance_policy', '')
        ))
        
        violation_id = cur.fetchone()[0]
        conn.commit()
        
        # Create notification if owner exists
        if owner:
            cur.execute("""
                INSERT INTO notifications 
                (user_id, title, message)
                VALUES (%s, 'New Violation', %s)
            """, (
                owner['id'],
                f"New {data['violation_type']} violation recorded for your vehicle"
            ))
            conn.commit()
        
        return jsonify({
            'message': 'Violation created successfully',
            'violation_id': violation_id
        }), 201
        
    except ValueError:
        return jsonify({'message': 'Invalid fine amount'}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/violations/<int:violation_id>/pay', methods=['PUT'])
@token_required
def pay_violation(current_user, violation_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Verify violation belongs to user
        cur.execute("""
            SELECT id FROM violations 
            WHERE id = %s AND license_plate = %s
        """, (violation_id, current_user['license_plate']))
        
        if not cur.fetchone():
            return jsonify({'message': 'Violation not found or not yours to pay!'}), 404
        
        # Update paid status
        cur.execute("""
            UPDATE violations 
            SET paid = TRUE
            WHERE id = %s
        """, (violation_id,))
        conn.commit()
        
        # Create payment notification
        cur.execute("""
            INSERT INTO notifications 
            (user_id, title, message)
            VALUES (%s, 'Payment Confirmed', 'Violation payment received')
        """, (current_user['id'],))
        conn.commit()
        
        return jsonify({'message': 'Violation paid successfully'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Notification Routes
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    
    try:
        # Get notifications
        cur.execute("""
            SELECT * FROM notifications 
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (current_user['id'],))
        notifications = cur.fetchall()
        
        # Mark as read
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
            RETURNING id
        """, (notification_id, current_user['id']))
        
        if not cur.fetchone():
            conn.rollback()
            return jsonify({'message': 'Notification not found'}), 404
        
        conn.commit()
        return jsonify({'message': 'Notification deleted'})
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
