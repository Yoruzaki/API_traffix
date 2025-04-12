from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
import datetime
from functools import wraps
import os
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS properly
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],  # Update with your frontend URL
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True
    }
})

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', "postgresql://traffix_lg5f_user:ebJu1mTba1sem66WC9dyPJg8VlHgcZnU@dpg-cvknp82dbo4c73f962r0-a.oregon-postgres.render.com/traffix_lg5f")

# Parse database URL
result = urlparse(DATABASE_URL)
db_config = {
    'database': result.path[1:],
    'user': result.username,
    'password': result.password,
    'host': result.hostname,
    'port': result.port
}

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-very-secure-secret-key')

def get_db_connection():
    """Create and return a new database connection"""
    try:
        conn = psycopg2.connect(**db_config, cursor_factory=RealDictCursor)
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

def token_required(f):
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip authentication for OPTIONS requests
        if request.method == 'OPTIONS':
            return jsonify({'status': 'preflight'}), 200
            
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authorization token is missing or invalid'}), 401
            
        token = auth_header.split(" ")[1]
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = get_user_by_id(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
            request.current_user = current_user
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'message': 'Authentication failed'}), 500
            
        return f(*args, **kwargs)
    return decorated

def get_user_by_id(user_id):
    """Fetch user by ID from database"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            return user
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return None
    finally:
        if conn:
            conn.close()

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    """User registration endpoint"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    data = request.get_json()
    required_fields = ['name', 'email', 'phone', 'password', 'cin', 'license_plate', 'vehicle_type']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'All fields are required'}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Check if email exists
            cur.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
            if cur.fetchone():
                return jsonify({'message': 'Email already exists'}), 400
            
            # In production, hash the password properly!
            hashed_password = data['password']
            
            cur.execute("""
                INSERT INTO users 
                (name, email, phone, password_hash, role, license_plate, vehicle_type, cin) 
                VALUES (%s, %s, %s, %s, 'civil', %s, %s, %s)
                RETURNING id, name, email, phone, role, license_plate, vehicle_type, cin
            """, (
                data['name'],
                data['email'],
                data['phone'],
                hashed_password,
                data['license_plate'],
                data['vehicle_type'],
                data['cin']
            ))
            
            user_data = cur.fetchone()
            conn.commit()
            
            token = jwt.encode({
                'user_id': user_data['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            return jsonify({
                'token': token,
                'user': user_data,
                'message': 'Registration successful'
            }), 201
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """User login endpoint"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    data = request.get_json()
    if not data or 'identifier' not in data or 'password' not in data:
        return jsonify({'message': 'Identifier and password are required'}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM users 
                WHERE email = %s OR badge_number = %s
            """, (data['identifier'], data['identifier']))
            
            user = cur.fetchone()
            if not user:
                return jsonify({'message': 'Invalid credentials'}), 401
            
            # In production, verify hashed password!
            if data['password'] != user['password_hash']:
                return jsonify({'message': 'Invalid credentials'}), 401
            
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            # Remove sensitive data before returning
            user.pop('password_hash', None)
            
            return jsonify({
                'token': token,
                'user': user,
                'message': 'Login successful'
            })
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/user', methods=['GET', 'OPTIONS'])
@token_required
def get_current_user():
    """Get current user profile"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    user = request.current_user
    user.pop('password_hash', None)
    return jsonify(user)

@app.route('/api/violations', methods=['GET', 'OPTIONS'])
@token_required
def get_violations():
    """Get violations list"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            if request.current_user['role'] == 'police':
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
                """, (request.current_user['license_plate'],))
            
            violations = cur.fetchall()
            return jsonify(violations)
    except Exception as e:
        logger.error(f"Get violations error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/violations', methods=['POST', 'OPTIONS'])
@token_required
def create_violation():
    """Create new violation"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    if request.current_user['role'] != 'police':
        return jsonify({'message': 'Only police officers can create violations'}), 403
    
    data = request.get_json()
    required_fields = ['license_plate', 'violation_type', 'location', 
                     'violation_date', 'fine_amount', 'insurance_policy']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
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
                request.current_user['id']
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
                'message': 'Violation created successfully', 
                'violation_id': violation_id
            }), 201
    except ValueError:
        return jsonify({'message': 'Invalid fine amount format'}), 400
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Create violation error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/violations/<int:violation_id>/pay', methods=['PUT', 'OPTIONS'])
@token_required
def pay_violation(violation_id):
    """Pay for a violation - working with existing database schema"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # 1. Verify the violation exists and check payment status
            cur.execute("""
                SELECT id, license_plate, paid 
                FROM violations 
                WHERE id = %s
                FOR UPDATE
            """, (violation_id,))
            
            violation = cur.fetchone()
            if not violation:
                return jsonify({'error': 'Violation not found'}), 404
                
            if violation['paid']:
                return jsonify({'error': 'Violation already paid'}), 400
                
            # 2. Verify the violation belongs to the current user
            if violation['license_plate'] != request.current_user['license_plate']:
                return jsonify({
                    'error': 'Violation does not belong to user',
                    'user_plate': request.current_user['license_plate'],
                    'violation_plate': violation['license_plate']
                }), 403
            
            # 3. Process the payment (without payment_date)
            cur.execute("""
                UPDATE violations 
                SET paid = TRUE
                WHERE id = %s
                RETURNING id, paid
            """, (violation_id,))
            
            updated_violation = cur.fetchone()
            
            # 4. Create payment notification
            cur.execute("""
                INSERT INTO notifications 
                (user_id, title, message)
                VALUES (%s, %s, %s)
            """, (
                request.current_user['id'],
                'Payment Confirmed',
                f'Payment received for violation #{violation_id}'
            ))
            
            conn.commit()
            
            return jsonify({
                'message': 'Payment successful',
                'violation_id': violation_id,
                'paid': updated_violation['paid']
            })
            
    except psycopg2.Error as e:
        logger.error(f"Database error during payment: {e}")
        if conn:
            conn.rollback()
        return jsonify({
            'error': 'Database error during payment processing',
            'details': str(e)
        }), 500
    except Exception as e:
        logger.error(f"Unexpected error during payment: {e}")
        if conn:
            conn.rollback()
        return jsonify({
            'error': 'Payment processing failed',
            'details': str(e)
        }), 500
    finally:
        if conn:
            conn.close()
@app.route('/api/notifications', methods=['GET', 'OPTIONS'])
@token_required
def get_notifications():
    """Get user notifications"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM notifications 
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (request.current_user['id'],))
            
            notifications = cur.fetchall()
            
            # Mark as read
            cur.execute("""
                UPDATE notifications 
                SET is_read = TRUE 
                WHERE user_id = %s AND is_read = FALSE
            """, (request.current_user['id'],))
            
            conn.commit()
            return jsonify(notifications)
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE', 'OPTIONS'])
@token_required
def delete_notification(notification_id):
    """Delete a notification"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'}), 200
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM notifications 
                WHERE id = %s AND user_id = %s
                RETURNING id
            """, (notification_id, request.current_user['id']))
            
            if not cur.fetchone():
                return jsonify({'message': 'Notification not found or not owned by user'}), 404
                
            conn.commit()
            return jsonify({'message': 'Notification deleted successfully'})
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Delete notification error: {e}")
        return jsonify({'message': str(e)}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
