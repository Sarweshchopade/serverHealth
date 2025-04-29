from Flask import flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import logging
from datetime import datetime

# Basic logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


app = Flask(__name__)

# Simple CORS configuration
CORS(app)

# Database configuration (no pooling)
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '9090',
    'database': 'healthcare_db',
    'auth_plugin': 'mysql_native_password'
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as err:
        logger.error(f"Failed to connect to database: {err}")
        raise

@app.route('/signup', methods=['POST'])
def signup():
    logger.info("Signup endpoint hit!")
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400

        # Validate required fields
        required_fields = ['username', 'email', 'password', 'dob', 'gender']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400

        # Hash password
        hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO user (username, first_name, second_name, last_name, email, password, date_of_birth, gender)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            params = (
                data['username'],
                data.get('first_name', ''),
                data.get('second_name', ''),
                data.get('last_name', ''),
                data['email'],
                hashed_pw,
                data['dob'],
                data['gender']
            )
            
            cursor.execute(query, params)
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'User registered successfully',
                'timestamp': datetime.now().isoformat()
            }), 201

        except mysql.connector.Error as db_error:
            conn.rollback()
            error_msg = str(db_error)
            
            if "Duplicate entry" in error_msg:
                if "username" in error_msg:
                    return jsonify({'success': False, 'message': 'Username already exists'}), 409
                elif "email" in error_msg:
                    return jsonify({'success': False, 'message': 'Email already exists'}), 409
            
            return jsonify({'success': False, 'message': 'Database error'}), 500

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    logger.info("Login attempt received")
    
    try:
        # Try to retrieve the request data
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'}), 400

        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400

        # Establishing DB connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            logger.debug(f"Executing query to fetch user with username: {username}")
            cursor.execute("""
                SELECT username, email, password 
                FROM `user`  -- Ensure `user` is not a reserved word or use backticks
                WHERE username = %s
            """, (username,))
            
            # Fetching the user details
            user = cursor.fetchone()
            if not user:
                logger.warning(f"No user found with username: {username}")
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

            # Check password match using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                logger.info(f"Login successful for username: {username}")
                return jsonify({
                    'success': True,
                    'message': 'Login successful',
                    'user': {
                        'username': user['username'],
                        'email': user['email']
                    }
                }), 200
            else:
                logger.warning(f"Invalid password attempt for username: {username}")
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        except mysql.connector.Error as db_error:
            # Log the specific database error for debugging
            logger.error(f"MySQL Error: {db_error}")
            return jsonify({'success': False, 'message': f"Database error: {str(db_error)}"}), 500

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        # Log any other exceptions that occur
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'success': False, 'message': f'Internal server error: {str(e)}'}), 500


if __name__ == '__main__':
    logger.info("Starting Flask server on 127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)

