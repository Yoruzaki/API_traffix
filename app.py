from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mysqldb import MySQL
import jwt
import datetime
from functools import wraps
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'traffix'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

mysql = MySQL(app)

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
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    return user

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    required_fields = ['name', 'email', 'phone', 'password', 'cin', 'license_plate', 'vehicle_type']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'{field} is required!'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
    if cur.fetchone():
        cur.close()
        return jsonify({'message': 'Email already exists!'}), 400
    
    # Store plain text password (in production, use hashing)
    hashed_password = data['password']
    
    try:
        cur.execute("""
            INSERT INTO users 
            (name, email, phone, password_hash, role, license_plate, vehicle_type, cin) 
            VALUES (%s, %s, %s, %s, 'civil', %s, %s, %s)
        """, (
            data['name'],
            data['email'],
            data['phone'],
            hashed_password,
            data['license_plate'],
            data['vehicle_type'],
            data['cin']
        ))
        mysql.connection.commit()
        user_id = cur.lastrowid
        
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        cur.close()
        return jsonify({'token': token, 'user_id': user_id}), 201
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        return jsonify({'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'identifier' not in data or 'password' not in data:
        return jsonify({'message': 'Identifier and password are required!'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s OR badge_number = %s", 
               (data['identifier'], data['identifier']))
    user = cur.fetchone()
    cur.close()
    
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    # Compare plain text passwords (in production, use hashing)
    if data['password'] != user['password_hash']:
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])
    
    user.pop('password_hash', None)
    
    return jsonify({'token': token, 'user': user})

@app.route('/api/user', methods=['GET'])
@token_required
def get_current_user(current_user):
    current_user.pop('password_hash', None)
    return jsonify(current_user)

@app.route('/api/violations', methods=['GET'])
@token_required
def get_violations(current_user):
    cur = mysql.connection.cursor()
    
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
    cur.close()
    return jsonify(violations)

@app.route('/api/violations', methods=['POST'])
@token_required
def create_violation(current_user):
    if current_user['role'] != 'police':
        return jsonify({'message': 'Only police officers can create violations!'}), 403
    
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
        
        cur = mysql.connection.cursor()
        
        # Get vehicle owner info if exists
        cur.execute("""
            SELECT id, name FROM users 
            WHERE license_plate = %s AND role = 'civil'
        """, (license_plate,))
        owner = cur.fetchone()
        
        owner_id = owner['id'] if owner else None
        owner_name = owner['name'] if owner else 'Unknown'
        
        # Create violation - REMOVED owner_id from columns list
        cur.execute("""
            INSERT INTO violations 
            (license_plate, owner_name, insurance_policy, violation_type, 
             violation_date, location, fine_amount, notes, officer_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        mysql.connection.commit()
        violation_id = cur.lastrowid
        
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
            mysql.connection.commit()
        
        cur.close()
        return jsonify({
            'message': 'Violation created successfully!', 
            'violation_id': violation_id
        }), 201
        
    except ValueError as e:
        return jsonify({'message': 'Invalid fine amount format'}), 400
    except Exception as e:
        print(f"Error creating violation: {str(e)}")
        mysql.connection.rollback()
        if 'cur' in locals(): cur.close()
        return jsonify({'message': str(e)}), 500

@app.route('/api/violations/<int:violation_id>/pay', methods=['PUT'])
@token_required
def pay_violation(current_user, violation_id):
    try:
        cur = mysql.connection.cursor()
        
        # Verify the violation exists and belongs to the current user
        cur.execute("""
            SELECT id FROM violations 
            WHERE id = %s AND license_plate = %s
        """, (violation_id, current_user['license_plate']))
        
        if not cur.fetchone():
            cur.close()
            return jsonify({'message': 'Violation not found or not yours to pay!'}), 404
        
        # Update only the paid status (using your existing tinyint(1) column)
        cur.execute("""
            UPDATE violations 
            SET paid = 1  # Using 1 instead of TRUE for MySQL compatibility
            WHERE id = %s
        """, (violation_id,))
        mysql.connection.commit()
        
        # Create a payment notification
        cur.execute("""
            INSERT INTO notifications 
            (user_id, title, message)
            VALUES (%s, 'Payment Confirmed', 'Your violation has been paid')
        """, (current_user['id'],))
        mysql.connection.commit()
        
        cur.close()
        return jsonify({'message': 'Violation paid successfully!'})
        
    except Exception as e:
        mysql.connection.rollback()
        if 'cur' in locals(): cur.close()
        return jsonify({'message': str(e)}), 500

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    try:
        cur = mysql.connection.cursor()
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
        mysql.connection.commit()
        
        cur.close()
        return jsonify(notifications)
    except Exception as e:
        cur.close()
        return jsonify({'message': str(e)}), 500

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@token_required
def delete_notification(current_user, notification_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            DELETE FROM notifications 
            WHERE id = %s AND user_id = %s
        """, (notification_id, current_user['id']))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Notification deleted successfully!'})
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        return jsonify({'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)