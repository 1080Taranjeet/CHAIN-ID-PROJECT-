from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import random
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import time
from dotenv import load_dotenv
import re
import json
import hashlib
import numpy as np
import cv2
from deepface import DeepFace
from scipy.spatial.distance import cosine, euclidean
from datetime import datetime, timedelta
import filetype
import zlib
from bson import ObjectId
from bson.errors import InvalidId
import uuid

# --- Configuration ---
class Config:
    """Centralized configuration for the application."""
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/chainid_db")
    ENCRYPTION_KEY = base64.b64decode(os.getenv(
        'ENCRYPTION_KEY', 'EVOd/1ytp2RnK9SSzfm6qYfY/FqtUopSi3+K/SeAAnk='
    ))
    GMAIL_ADDRESS = os.getenv('GMAIL_ADDRESS', 'chain.id.project.25@gmail.com')
    GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD', 'flhz dpme kswm ecxv')
    OTP_EXPIRY = 60  # Seconds
    MAX_ATTEMPTS = 5
    REQUEST_COOLDOWN = 30  # Seconds
    BLOCK_TIME = 300  # Seconds
    SESSION_DURATION = timedelta(days=7)
    ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000')
    SESSION_BLOCKCHAIN_DIFFICULTY = 2

# Load environment variables
load_dotenv()

# --- Flask Setup ---
app = Flask(__name__)
app.config["MONGO_URI"] = Config.MONGODB_URI
mongo = PyMongo(app)
CORS(app, resources={r"/*": {"origins": Config.ALLOWED_ORIGINS}})

# --- Security Configuration ---
app.config.update({
    'ENCRYPTION_KEY': Config.ENCRYPTION_KEY,
    'GMAIL_ADDRESS': Config.GMAIL_ADDRESS,
    'GMAIL_APP_PASSWORD': Config.GMAIL_APP_PASSWORD,
    'OTP_EXPIRY': Config.OTP_EXPIRY,
    'MAX_ATTEMPTS': Config.MAX_ATTEMPTS,
    'REQUEST_COOLDOWN': Config.REQUEST_COOLDOWN,
    'BLOCK_TIME': Config.BLOCK_TIME
})

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Utilities ---
ENCRYPTION_KEY = app.config['ENCRYPTION_KEY']
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
DEVICE_ID_REGEX = re.compile(r'^[a-f0-9]{64}$')

def decrypt_data(encrypted_string):
    """
    Decrypts AES-encrypted data.

    Args:
        encrypted_string (str): Format iv:ciphertext

    Returns:
        dict: Decrypted JSON data or None if failed
    """
    try:
        iv_b64, cipher_b64 = encrypted_string.split(":")
        iv = base64.b64decode(iv_b64)
        cipher_text = base64.b64decode(cipher_b64)
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(cipher_text), AES.block_size)
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return None

# --- Blockchain Classes ---
class SessionBlockChain:
    """Manages session-based blockchain with proof-of-work."""
    def __init__(self):
        self.difficulty = Config.SESSION_BLOCKCHAIN_DIFFICULTY
        self.session_expiry = Config.SESSION_DURATION
        self.logger = logging.getLogger(__name__)

    def create_session_block(self, user_email, signup_method, device_id, action):
        """
        Creates a new session block with proof-of-work mining.

        Args:
            user_email (str): User's email address
            signup_method (str): Biometric method ('face', 'fingerprint', 'both', 'none')
            device_id (str): Unique device identifier
            action (str): Session action ('login', 'logout', 'renew')

        Returns:
            dict: Created block or False if failed
        """
        try:
            last_block = mongo.db.session_blocks.find_one(sort=[("block_index", -1)])
            new_index = last_block["block_index"] + 1 if last_block else 0
            self.logger.info(f"Creating session block #{new_index} for {user_email}")

            current_time = datetime.utcnow().replace(microsecond=0)
            expires_at = current_time + self.session_expiry

            new_block = {
                'block_index': new_index,
                'user_email': user_email,
                'signup_method': signup_method,
                'device_id': hashlib.sha256(device_id.encode()).hexdigest(),
                'action': action,
                'timestamp': current_time,
                'expires_at': expires_at,
                'previous_hash': last_block["current_hash"] if last_block else '0',
                'nonce': 0
            }

            # Mine block with proof-of-work
            self.logger.debug("Mining session block...")
            while True:
                new_block['current_hash'] = self._calculate_hash(new_block)
                if new_block['current_hash'].startswith('0' * self.difficulty):
                    break
                new_block['nonce'] += 1

            self.logger.info(f"Block mined with nonce: {new_block['nonce']}")

            # Insert into MongoDB
            result = mongo.db.session_blocks.insert_one(new_block)
            if not result.inserted_id:
                raise Exception("Failed to insert session block")
            
            new_block['_id'] = str(result.inserted_id)  # Add MongoDB ID to block
                
            self.logger.info(f"Session block #{new_index} saved")
            return new_block

        except Exception as e:
            self.logger.error(f"Failed to create session block: {str(e)}")
            return False

    def _calculate_hash(self, block):
        """Calculates SHA-256 hash for a session block."""
        block_string = (
            f"{block['block_index']}{block['user_email']}"
            f"{block['signup_method']}{block['device_id']}"
            f"{block['action']}{block['timestamp'].isoformat()}"
            f"{block['expires_at'].isoformat()}"
            f"{block['previous_hash']}{block['nonce']}"
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def validate_chain(self):
        """
        Validates session blockchain integrity.

        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        try:
            blocks = list(mongo.db.session_blocks.find().sort("block_index", 1))
            for i in range(1, len(blocks)):
                curr = blocks[i]
                prev = blocks[i - 1]
                if curr['previous_hash'] != prev['current_hash']:
                    return False, f"Chain broken at index {curr['block_index']}"
                if not curr['current_hash'].startswith('0' * self.difficulty):
                    return False, f"Invalid PoW at index {curr['block_index']}"
                # Recalculate hash
                computed_hash = self._calculate_hash({
                    'block_index': curr['block_index'],
                    'user_email': curr['user_email'],
                    'signup_method': curr['signup_method'],
                    'device_id': curr['device_id'],
                    'action': curr['action'],
                    'timestamp': curr['timestamp'],
                    'expires_at': curr['expires_at'],
                    'previous_hash': curr['previous_hash'],
                    'nonce': curr['nonce']
                })
                if computed_hash != curr['current_hash']:
                    return False, f"Hash mismatch at index {curr['block_index']}"
            return True, None
        except Exception as e:
            self.logger.error(f"Chain validation failed: {str(e)}")
            return False, "Validation error"

# --- In-memory Blockchain (aligned with Hyperledger Fabric chaincode logic) ---

def calculate_data_hash(block):
    """Calculates SHA-256 hash for a data block, matching chaincode."""
    block_string = (
        f"{block['index']}{block['timestamp'].isoformat()}"
        f"{block['data']}{block['previous_hash']}"
    )
    return hashlib.sha256(block_string.encode()).hexdigest()

def add_block(data_dict):
    try:
        last_block = mongo.db.blocks.find_one(sort=[("index", -1)])
        new_index = last_block["index"] + 1 if last_block else 0
        
        current_time = datetime.utcnow().replace(microsecond=0)
        
        data_json = json.dumps(data_dict, sort_keys=True)
        
        new_block = {
            'index': new_index,
            'timestamp': current_time,
            'data': data_json,  # Store as JSON string to match chaincode
            'previous_hash': last_block["hash"] if last_block else '0'
        }
        
        new_block['hash'] = calculate_data_hash(new_block)
        
        result = mongo.db.blocks.insert_one(new_block)
        if not result.inserted_id:
            raise Exception("Failed to insert block")
            
        logging.info(f"Block #{new_index} added")
        return new_block
    except Exception as e:
        logging.error(f"Failed to add block: {str(e)}")
        return None

def initialize_genesis_block():
    if mongo.db.blocks.find_one({"index": 0}) is None:
        genesis_data = {
            "type": "genesis",
            "timestamp": datetime.utcnow().isoformat(),
            "description": "Genesis block for ChainID blockchain"
        }
        add_block(genesis_data)

def is_blockchain_valid(blocks):
    try:
        for i in range(1, len(blocks)):
            curr = blocks[i]
            prev = blocks[i - 1]
            if curr['previous_hash'] != prev['hash']:
                return False, f"Chain broken at index {curr['index']}"
            computed_hash = calculate_data_hash(curr)
            if computed_hash != curr['hash']:
                return False, f"Hash mismatch at index {curr['index']}"
        # Check genesis
        if blocks and blocks[0]['previous_hash'] != '0':
            return False, "Invalid genesis block"
        return True, None
    except Exception as e:
        logger.error(f"Main chain validation failed: {str(e)}")
        return False, "Validation error"

# --- Session Management ---
active_sessions = {}

def rebuild_active_sessions():
    """
    Rebuilds active sessions from session blockchain on startup.
    """
    try:
        active_sessions.clear()
        valid_logins = list(mongo.db.session_blocks.find({
            'action': 'login',
            'expires_at': {'$gt': datetime.utcnow()}
        }).sort([("timestamp", -1)]))

        for login in valid_logins:
            logout_exists = mongo.db.session_blocks.find_one({
                'user_email': login['user_email'],
                'action': 'logout',
                'timestamp': {'$gt': login['timestamp']}
            })

            if not logout_exists:
                active_sessions[login['user_email']] = {
                    'device_id': login['device_id'],
                    'expires': login['expires_at']
                }
        logging.info(f"Rebuilt {len(active_sessions)} active sessions")
    except Exception as e:
        logging.error(f"Session rebuild failed: {str(e)}")

def cleanup_expired_sessions():
    """
    Removes expired sessions from database and cache.
    """
    try:
        result = mongo.db.session_blocks.delete_many({
            'expires_at': {'$lt': datetime.utcnow()}
        })
        logging.info(f"Cleaned up {result.deleted_count} expired session blocks")
        active_sessions.clear()
        rebuild_active_sessions()
    except Exception as e:
        logging.error(f"Session cleanup failed: {str(e)}")

# --- OTP Management ---
otp_registry = {}
blocked_emails = {}
rate_limit_registry = {}  # For manual rate limiting

@app.after_request
def apply_security_headers(response):
    """Applies security headers to all responses."""
    headers = {
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    response.headers.update(headers)
    return response

# The /send-otp API endpoint
@app.route('/send-otp', methods=['POST'])
def handle_otp_request():
    """Sends an OTP for email verification after validating the blockchain."""
    try:
        # Parse request data
        data = request.get_json()
        if not data or 'encrypted_email' not in data:
            app.logger.warning("Request missing encrypted_email")
            return jsonify({'success': False, 'message': 'Missing encrypted_email'}), 400
        
        purpose = data.get('purpose', 'signup')

        # Decrypt and validate email
        email_data = decrypt_data(data['encrypted_email'])
        if not email_data or 'email' not in email_data or not EMAIL_REGEX.match(email_data['email']):
            app.logger.warning("Invalid or malformed encrypted_email data")
            return jsonify({'success': False, 'message': 'Invalid email'}), 400
        email = email_data['email']
        app.logger.info(f"Processing OTP request for {email}")

        # Rate limiting
        current_time = time.time()
        if email in rate_limit_registry:
            attempts = rate_limit_registry[email]
            if len(attempts) >= 5 and (current_time - attempts[-5]) < 60:
                app.logger.warning(f"Rate limit exceeded for {email}")
                return jsonify({'success': False, 'message': 'Rate limit exceeded'}), 429
            rate_limit_registry[email].append(current_time)
            rate_limit_registry[email] = rate_limit_registry[email][-5:]  # Keep last 5 attempts
        else:
            rate_limit_registry[email] = [current_time]

        # Ensure genesis block exists
        initialize_genesis_block()

        # Validate blockchain
        blocks = list(mongo.db.blocks.find().sort("index", 1))
        is_valid, error_msg = is_blockchain_valid(blocks)
        if not is_valid:
            app.logger.error(f"Blockchain validation failed: {error_msg}")
            return jsonify({"success": False, "message": f"Blockchain invalid: {error_msg}"}), 400

        # Check if email is already registered
        if purpose == 'signup':
            user_exists = mongo.db.users.find_one({"email": email})
            if user_exists:
                return jsonify({"success": False, "message": "Email already registered"}), 400
        elif purpose == 'login':
            user = mongo.db.users.find_one({"email": email})
            if not user:
                return jsonify({"success": False, "message": "Email not found. Please sign up."}), 404

        # Check if email is blocked
        if email in blocked_emails and blocked_emails[email] > current_time:
            app.logger.warning(f"Blocked email attempted OTP: {email}")
            return jsonify({'success': False, 'message': 'Account locked'}), 403

        # Check OTP cooldown
        if email in otp_registry:
            elapsed = current_time - otp_registry[email]['timestamp']
            if elapsed < app.config['REQUEST_COOLDOWN']:
                remaining = app.config['REQUEST_COOLDOWN'] - int(elapsed)
                app.logger.info(f"Cooldown active for {email}, {remaining}s remaining")
                return jsonify({
                    'success': False,
                    'message': f'Wait {remaining} seconds'
                }), 429

        # Generate OTP
        otp_code = str(random.randint(100000, 999999))
        app.logger.info(f"Generated OTP {otp_code} for {email}")

        # Prepare email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Your ChainID Verification Code'
        msg['From'] = app.config['GMAIL_ADDRESS']
        msg['To'] = email

        # Plain text version
        text = f"""\
Hello,

Your ChainID verification code is: {otp_code}

This code expires in {app.config['OTP_EXPIRY']} seconds. Please enter it to verify your email.

If you didn't request this code, please ignore this email.

Best regards,
The ChainID Team
"""

        # HTML version
        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <h2 style="color: #007bff;">ChainID Verification Code</h2>
    <p>Hello,</p>
    <p>Your verification code is:</p>
    <h3 style="background: #f8f9fa; padding: 10px; border-radius: 5px;">{otp_code}</h3>
    <p>This code expires in <strong>{app.config['OTP_EXPIRY']} seconds</strong>. Please enter it to verify your email.</p>
    <p>If you didn't request this code, please ignore this email.</p>
    <p>Best regards,<br>The ChainID Team</p>
  </body>
</html>
"""

        # Attach email parts
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        # Send email
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(app.config['GMAIL_ADDRESS'], app.config['GMAIL_APP_PASSWORD'])
                server.send_message(msg)
            app.logger.info(f"OTP email sent successfully to {email}")
        except smtplib.SMTPException as e:
            app.logger.error(f"Failed to send OTP email to {email}: {str(e)}")
            return jsonify({'success': False, 'message': 'Email service error'}), 503

        # Store OTP
        otp_registry[email] = {
            'otp': otp_code,
            'timestamp': current_time,
            'attempts': 0
        }

        app.logger.info(f"OTP request completed for {email}")
        return jsonify({
            'success': True,
            'message': 'OTP sent',
            'expiry': app.config['OTP_EXPIRY']
        }), 200

    except Exception as e:
        app.logger.error(f"Server error in /send-otp for {email}: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/verify-otp', methods=['POST'])
def handle_otp_verification():
    """Verifies OTP with security checks."""
    try:
        data = request.get_json()
        logger.info("Received OTP verification: %s", data)

        if not data or 'encrypted_email' not in data or 'otp' not in data:
            return jsonify({'success': False, 'message': 'Missing fields'}), 400

        email_data = decrypt_data(data['encrypted_email'])
        if not email_data or 'email' not in email_data or not EMAIL_REGEX.match(email_data['email']):
            return jsonify({'success': False, 'message': 'Invalid email'}), 400
        email = email_data['email']

        current_time = time.time()
        record = otp_registry.get(email)

        if email in blocked_emails and blocked_emails[email] > current_time:
            return jsonify({'success': False, 'message': 'Account locked'}), 403

        if not record:
            return jsonify({'success': False, 'message': 'No OTP request'}), 400

        if current_time - record['timestamp'] > app.config['OTP_EXPIRY']:
            del otp_registry[email]
            return jsonify({'success': False, 'message': 'OTP expired'}), 410

        received_otp = str(data['otp']).strip()
        stored_otp = record['otp']
        logger.info("Comparing OTPs: received='%s' (%s), stored='%s' (%s)",
                    received_otp, type(received_otp), stored_otp, type(stored_otp))

        if received_otp != stored_otp:
            record['attempts'] += 1
            if record['attempts'] >= app.config['MAX_ATTEMPTS']:
                blocked_emails[email] = current_time + app.config['BLOCK_TIME']
                del otp_registry[email]
                return jsonify({
                    'success': False,
                    'message': 'Too many attempts',
                    'attempts_left': 0
                }), 403
            attempts_left = app.config['MAX_ATTEMPTS'] - record['attempts']
            return jsonify({
                'success': False,
                'message': f'Incorrect OTP. {attempts_left} attempts left',
                'attempts_left': attempts_left
            }), 401

        del otp_registry[email]
        return jsonify({
            'success': True,
            'message': 'OTP verified',
            'attempts_left': app.config['MAX_ATTEMPTS']
        }), 200

    except Exception as e:
        logger.error(f"OTP verification error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

# --- API Endpoints ---
@app.route("/api/register", methods=["POST"])
def register():
    """Registers a new user and creates session blockchain entry."""
    try:
        data = request.get_json()
        encrypted = data.get("encryptedSession")
        result = data.get("answer")

        session_data = decrypt_data(encrypted)
        result_data = decrypt_data(result)

        if not session_data or "email" not in session_data or "deviceId" not in session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 400

        email = session_data["email"]
        device_id = session_data["deviceId"]

        if not DEVICE_ID_REGEX.match(device_id):
            return jsonify({"success": False, "message": "Invalid device ID format"}), 400

        # Extract biometric data
        biometrics = result_data.get("biometrics", {})
        biometric_data = biometrics.get("data", {}) or {}

        face_data = biometric_data.get("faceData")
        fingerprint_data = biometric_data.get("publicKey")

        # Determine signup method
        if face_data and fingerprint_data:
            signup_method = "both"
        elif face_data:
            signup_method = "face"
        elif fingerprint_data:
            signup_method = "fingerprint"
        else:
            signup_method = "none"

        # Validate session blockchain before proceeding
        chain = SessionBlockChain()
        is_valid, error_msg = chain.validate_chain()
        if not is_valid:
            return jsonify({"success": False, "message": f"Session blockchain invalid: {error_msg}"}), 400

        # Create and store user
        user = {
            'email': email,
            'signup_method': None if signup_method == 'none' else signup_method,
            'face_id': face_data if signup_method in ['face', 'both'] else None,
            'fingerprint_id': fingerprint_data if signup_method in ['fingerprint', 'both'] else None,
            'created_at': datetime.utcnow()
        }
        result = mongo.db.users.insert_one(user)
        if not result.inserted_id:
            raise Exception("Failed to insert user")

        # Create session block
        session_block = chain.create_session_block(email, signup_method, device_id, 'login')
        if not session_block:
            raise Exception("Failed to create session block")

        # Add to blockchain
        add_block({
            "email": email,
            "device_id": device_id,
            'face_id': face_data if signup_method in ['face', 'both'] else None,
            'fingerprint_id': fingerprint_data if signup_method in ['fingerprint', 'both'] else None,
            "session_block_id": session_block['current_hash'],   
        })

        # Add to active sessions
        active_sessions[email] = {
            "device_id": device_id,
            "expires": datetime.utcnow() + Config.SESSION_DURATION
        }

        # Email content
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Welcome to ChainID - Registration Successful'
        msg['From'] = app.config['GMAIL_ADDRESS']
        msg['To'] = email

        text = f"""\
Hello,

Welcome to ChainID! Your registration was successful.

You're now ready to explore our secure authentication platform. If you have any questions, feel free to contact our support team.

Best regards,
The ChainID Team
"""
        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center">
          <table width="600" cellpadding="20" cellspacing="0" style="border: 1px solid #ddd;">
            <tr>
              <td>
                <h2 style="color: #007bff;">Welcome to ChainID!</h2>
                <p>Hello,</p>
                <p>Your registration was successful. You're now ready to explore our secure authentication platform.</p>
                <p>If you have any questions, feel free to contact our <a href="mailto:support@chainid.example.com" style="color: #007bff;">support team</a>.</p>
                <p>Best regards,<br>The ChainID Team</p>
                <hr style="border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #666;">
                  &copy; {datetime.utcnow().year} ChainID. All rights reserved.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(app.config['GMAIL_ADDRESS'], app.config['GMAIL_APP_PASSWORD'])
                server.send_message(msg)
                logger.info(f"Registration success email sent to {email}")
        except smtplib.SMTPException as e:
            logger.error(f"Failed to send registration email: {str(e)}")
            pass  # don't fail the registration on email fail

        return jsonify({"success": True, "message": "Registration successful" , "session_id": str(session_block['_id'])})

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"success": False, "message": "Registration failed"}), 500

@app.route("/api/login", methods=["POST"])
def login():
    """Logs in a user and creates session-only blockchain entry."""
    try:
        data = request.get_json()
        encrypted = data.get("encryptedSession")
        
        session_data = decrypt_data(encrypted)
        if not session_data or "email" not in session_data or "deviceId" not in session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 400

        email = session_data["email"]
        device_id = session_data["deviceId"]

        # Validate device ID format
        if not DEVICE_ID_REGEX.match(device_id):
            return jupytext({"success": False, "message": "Invalid device ID format"}), 400

        # Check user exists
        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        # Validate session blockchain before proceeding
        chain = SessionBlockChain()
        is_valid, error_msg = chain.validate_chain()
        if not is_valid:
            return jsonify({"success": False, "message": f"Session blockchain invalid: {error_msg}"}), 400

         # Create session block
        session_block = chain.create_session_block(email, 'none', device_id, 'login')

        if not session_block:
            raise Exception("Failed to create session block")

        # Update active sessions
        active_sessions[email] = {
            "device_id": device_id,
            "expires": datetime.utcnow() + Config.SESSION_DURATION
        }

        # Send login notification email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'ChainID - Successful Login Alert'
        msg['From'] = app.config['GMAIL_ADDRESS']
        msg['To'] = email

        text = f"""\
Hello,

You've successfully logged in to your ChainID account.

Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Device ID: {device_id}

If this wasn't you, please contact our support team immediately.

Best regards,
The ChainID Team
"""

        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center">
          <table width="600" cellpadding="20" cellspacing="0" style="border: 1px solid #ddd;">
            <tr>
              <td>
                <h3 style="color: #007bff;">Successful Login Alert</h3>
                <p>Hello,</p>
                <p>You've successfully logged in to your ChainID account.</p>
                <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Device ID:</strong> {device_id}</p>
                <p>If this wasn't you, please contact our <a href="mailto:support@chainid.example.com" style="color: #007bff;">support team</a> immediately.</p>
                <p>Best regards,<br>The ChainID Team</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(app.config['GMAIL_ADDRESS'], app.config['GMAIL_APP_PASSWORD'])
                server.send_message(msg)
                logger.info(f"Login notification email sent to {email}")
        except smtplib.SMTPException as e:
            logger.error(f"Failed to send login notification: {str(e)}")
            pass

        return jsonify({
            "success": True,
            "message": "Login successful",
            "session_id": str(session_block['_id']),
            "email": email,
            "signup_method": user.get("signup_method"),
            "exists": True
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "message": "Login failed"}), 500

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Checks if an email exists in users collection or blockchain."""
    try:
        data = request.get_json()
        if not data or 'encrypted_email' not in data:
            logger.warning("Missing encrypted_email")
            return jsonify({"success": False, "message": "Missing encrypted_email"}), 400

        email_data = decrypt_data(data['encrypted_email'])
        if not email_data or 'email' not in email_data or not EMAIL_REGEX.match(email_data['email']):
            logger.warning("Invalid encrypted_email")
            return jsonify({"success": False, "message": "Invalid email"}), 400

        email = email_data['email'].lower().strip()

        try:
            # Check users collection first
            user = mongo.db.users.find_one({"email": email})
            if user:
                logger.info(f"Email found in users collection: {email}")
                return jsonify({
                    "success": True,
                    "email": email,
                    "signup_method": user.get("signup_method"),
                    "exists": True
                }), 200

            # Check blockchain if not found in users collection
            logger.info(f"Checking blockchain for email: {email}")
            blocks = list(mongo.db.blocks.find().sort("index", 1))
            
            if blocks:
                # Validate blockchain integrity first
                is_valid, error_msg = is_blockchain_valid(blocks)
                if not is_valid:
                    logger.error(f"Blockchain validation failed: {error_msg}")
                    return jsonify({
                        "success": False,
                        "message": "Blockchain validation failed"
                    }), 400

                # Search blocks for email
                for block in blocks:
                    try:
                        block_data = json.loads(block['data'])  # Changed to match chaincode (data as JSON string)
                        stored_email = block_data.get('email', '').strip().lower()
                        if stored_email == email:
                            logger.info(f"Email found in blockchain block {block['index']}")
                            return jsonify({
                                "success": True,
                                "email": email,
                                "signup_method": None,
                                "exists": True,
                                "message": "Found in blockchain but not in users collection"
                            }), 200
                            
                    except Exception as e:
                        logger.error(f"Error processing block {block['index']}: {str(e)}")
                        continue

            # Email not found anywhere
            logger.info(f"Email not found: {email}")
            return jsonify({
                "success": True,
                "email": email,
                "signup_method": None,
                "exists": False
            }), 200

        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Database operation failed"
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Internal server error"
        }), 500


@app.route("/api/user-data", methods=["POST"])
def get_user_data():
    """Retrieves user data and login history based on encrypted session data using session blockchain."""
    try:
        # Parse and validate request data
        data = request.get_json()
        if not data or "encryptedSession" not in data:
            logger.warning("Missing encryptedSession in request")
            return jsonify({"success": False, "message": "Missing session data"}), 400

        # Decrypt session data
        session_data = decrypt_data(data["encryptedSession"])
        session_id = session_data.get("session_id")
        device_id = session_data.get("deviceId")

        if not session_id or not device_id:
            return jsonify({"success": False, "message": "Missing session_id or device_id"}), 400

        try:
            session_obj_id = ObjectId(session_id)
        except InvalidId:
            return jsonify({"success": False, "message": "Invalid session_id"}), 400

        session_block = mongo.db.session_blocks.find_one({"_id": session_obj_id})
        if not session_block:
            return jsonify({"success": False, "message": "Session not found"}), 404

        if session_block["expires_at"] < datetime.utcnow():
            return jsonify({"success": False, "message": "Session expired"}), 401

        hashed_device_id = hashlib.sha256(device_id.encode()).hexdigest()
        if hashed_device_id != session_block["device_id"]:
            return jsonify({"success": False, "message": "Device ID mismatch"}), 401

        logout_exists = mongo.db.session_blocks.find_one({
            "user_email": session_block["user_email"],
            "action": "logout",
            "timestamp": {"$gt": session_block["timestamp"]}
        })
        if logout_exists:
            return jsonify({"success": False, "message": "Session invalid due to logout"}), 401

        email = session_block["user_email"]

        # Include _id and updated_at in the projection
        user = mongo.db.users.find_one({"email": email}, {
            "_id": 1,  # Include document ID
            "email": 1,
            "signup_method": 1,
            "created_at": 1,
            "updated_at": 1,  # Include updated timestamp
            "frozen_methods": 1  # Include freeze status
        })
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        login_history = list(mongo.db.session_blocks.find({
            "user_email": email,
            "action": "login"
        }, {
            "_id": 0,
            "timestamp": 1,
            "device_id": 1,
            "signup_method": 1,
            "expires_at": 1
        }).sort("timestamp", -1).limit(50))

        formatted_history = [
            {
                "timestamp": entry["timestamp"].isoformat(),
                "device_id": entry["device_id"],
                "method": entry.get("signup_method", "none"),
                "expires_at": entry["expires_at"].isoformat()
            } for entry in login_history
        ]

        # Prepare user data with document ID and timestamps
        user_data = {
            "email": user["email"],
            "signup_method": user.get("signup_method", "none"),
            "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
            "updated_at": user["updated_at"].isoformat() if user.get("updated_at") else None,
            "_id": str(user["_id"]),  # Convert ObjectId to string
            "frozen_methods": user.get("frozen_methods", []),  # Include frozen methods
            "login_history": formatted_history
        }

        return jsonify({
            "success": True,
            "message": "User data and login history retrieved successfully",
            "data": user_data
        })

    except Exception as e:
        logger.error(f"Error retrieving user data: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500  


@app.route('/api/update-user', methods=['POST'])
def update_user():
    try:
        # Get and decrypt request data
        data = request.get_json()
        encrypted_update = data.get('encryptedUpdate')
        if not encrypted_update:
            return jsonify(success=False, message="Missing encryptedUpdate"), 400

        update_payload = decrypt_data(encrypted_update)
        if not update_payload:
            return jsonify(success=False, message="Invalid encryptedUpdate"), 400

        # Extract required fields
        email = update_payload.get('email')
        device_id = update_payload.get('deviceId')
        method = update_payload.get('method')  # 'face' or 'fingerprint'
        data_field = update_payload.get('data')
        
        # Validate required fields
        if not all([email, device_id, method, data_field]):
            return jsonify(success=False, message="Missing required fields"), 400
        if method not in ['face', 'fingerprint']:
            return jsonify(success=False, message="Invalid method"), 400

        # Find user
        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify(success=False, message="User not found"), 404

        # Prepare update data
        update_data = {}
        if method == 'face':
            if 'faceData' not in data_field:
                return jsonify(success=False, message="Missing faceData"), 400
            update_data['face_id'] = data_field['faceData']
        else:  # fingerprint
            if 'publicKey' not in data_field :
                return jsonify(success=False, message="Missing fingerprint data"), 400
            update_data['fingerprint_id'] = data_field['publicKey']

        # Handle signup_method conversion - FIX FOR NULL VALUES
        current_signup = user.get('signup_method')
        
        # Handle all possible cases: None, string, or array
        if current_signup is None:
            # New user with no methods enabled
            current_signup = []
        elif isinstance(current_signup, str):
            # Convert legacy string format to array
            if current_signup == 'none':
                current_signup = []
            elif current_signup == 'both':
                current_signup = ['face', 'fingerprint']
            else:
                current_signup = [current_signup]
        
        # Add method if not already present
        if method not in current_signup:
            current_signup.append(method)
        
        # Convert back to string format for compatibility
        if 'face' in current_signup and 'fingerprint' in current_signup:
            update_data['signup_method'] = 'both'
        elif 'face' in current_signup:
            update_data['signup_method'] = 'face'
        elif 'fingerprint' in current_signup:
            update_data['signup_method'] = 'fingerprint'
        else:
            update_data['signup_method'] = 'none'
        
        update_data['updated_at'] = datetime.utcnow()
        
        # Initialize frozen_methods if not exists (as array)
        if 'frozen_methods' not in user:
            update_data['frozen_methods'] = []

        # Update user in database
        result = mongo.db.users.update_one(
            {"email": email},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return jsonify(success=False, message="User update failed"), 500

        # Create new block in main blockchain
        block_data = {
            "event": "user_update",
            "email": email,
            "updated_method": method,
            "device_id": device_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        new_block = add_block(block_data)
        if not new_block:
            logger.error("Failed to add block for user update")

        # Create session block for update action
        chain = SessionBlockChain()
        session_block = chain.create_session_block(
            user_email=email,
            signup_method=method,  # 'face' or 'fingerprint'
            device_id=device_id,
            action='update'
        )
        if not session_block:
            logger.error("Failed to create session block for update")

        return jsonify(success=True, message="User updated successfully"), 200

    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify(success=False, message="Server error"), 500
    
@app.route('/api/toggle-method-freeze', methods=['POST'])
def toggle_method_freeze():
    try:
        # Get and decrypt request data
        data = request.get_json()
        encrypted_data = data.get('encryptedData')
        if not encrypted_data:
            return jsonify(success=False, message="Missing encrypted data"), 400

        payload = decrypt_data(encrypted_data)
        if not payload:
            return jsonify(success=False, message="Invalid encrypted data"), 400

        # Extract required fields - FIX: changed 'device_id' to 'deviceId'
        email = payload.get('email')
        method = payload.get('method')  # 'face' or 'fingerprint'
        device_id = payload.get('deviceId')  # Corrected field name
        
        # Validate required fields
        if not all([email, method, device_id]):
            # Add detailed logging for missing fields
            missing = []
            if not email: missing.append('email')
            if not method: missing.append('method')
            if not device_id: missing.append('deviceId')
            logger.error(f"Missing required fields: {', '.join(missing)}")
            return jsonify(success=False, message="Missing required fields"), 400
            
        if method not in ['face', 'fingerprint']:
            return jsonify(success=False, message="Invalid method specified"), 400

        # Find user
        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify(success=False, message="User not found"), 404

        # Convert signup_method to array if needed
        current_signup = user.get('signup_method', 'none')
        if isinstance(current_signup, str):
            if current_signup == 'none':
                current_signup = []
            elif current_signup == 'both':
                current_signup = ['face', 'fingerprint']
            else:
                current_signup = [current_signup]
        
        # Initialize frozen_methods from user document
        frozen_methods = user.get('frozen_methods', [])
        
        # Prepare response messages
        action_message = ""
        event_type = ""
        session_action = ""
        
        # Toggle freeze status
        if method in frozen_methods:
            # UNFREEZE BRANCH
            # Check if biometric data exists for the method
            if (method == 'face' and not user.get('face_id')) or \
               (method == 'fingerprint' and not user.get('fingerprint_id')):
                return jsonify(
                    success=False, 
                    message=f"Biometric data missing. Please re-enable {method} authentication"
                ), 400
                
            # Update arrays: remove from frozen, add to enabled if missing
            frozen_methods = [m for m in frozen_methods if m != method]
            if method not in current_signup:
                current_signup.append(method)
                
            action_message = f"{method.capitalize()} authentication has been unfrozen"
            event_type = "method_unfrozen"
            session_action = "unfreeze"
        else:
            # FREEZE BRANCH
            if method not in current_signup:
                return jsonify(
                    success=False, 
                    message=f"{method.capitalize()} authentication is not enabled"
                ), 400
                
            # Update arrays: remove from enabled, add to frozen
            current_signup = [m for m in current_signup if m != method]
            frozen_methods.append(method)
                
            action_message = f"{method.capitalize()} authentication has been frozen"
            event_type = "method_frozen"
            session_action = "freeze"

        # Convert enabled methods to string format
        if 'face' in current_signup and 'fingerprint' in current_signup:
            signup_str = 'both'
        elif 'face' in current_signup:
            signup_str = 'face'
        elif 'fingerprint' in current_signup:
            signup_str = 'fingerprint'
        else:
            signup_str = 'none'

        # Prepare update
        update_data = {
            'signup_method': signup_str,
            'frozen_methods': frozen_methods,
            'updated_at': datetime.utcnow()
        }

        # Update user in database
        result = mongo.db.users.update_one(
            {"email": email},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return jsonify(success=False, message="No changes made"), 400

        # Create new block in main blockchain
        block_data = {
            "event": event_type,
            "email": email,
            "method": method,
            "device_id": device_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        new_block = add_block(block_data)
        if not new_block:
            logger.error(f"Failed to add block for {event_type}")

        # Create session block for the action
        chain = SessionBlockChain()
        session_block = chain.create_session_block(
            user_email=email,
            signup_method=method,
            device_id=device_id,
            action=session_action
        )
        if not session_block:
            logger.error(f"Failed to create session block for {session_action}")

        return jsonify(success=True, message=action_message), 200

    except Exception as e:
        logger.error(f"Toggle method freeze error: {str(e)}")
        return jsonify(success=False, message="Server error"), 500
            
@app.route("/api/create-api", methods=["POST"])
def create_api():
    try:
        data = request.get_json()
        if not all(key in data for key in ["encryptedSession", "project_name"]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        encrypted_session = data["encryptedSession"]
        project_name = data["project_name"]
        domain_allowed = data.get("domain_allowed", "all")

        # Decrypt session data
        session_data = decrypt_data(encrypted_session)
        if not session_data or "session_id" not in session_data or "deviceId" not in session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 400

        session_id = session_data["session_id"]
        device_id = session_data["deviceId"]

        # Verify session
        try:
            session_obj_id = ObjectId(session_id)
        except InvalidId:
            return jsonify({"success": False, "message": "Invalid session_id"}), 400

        session_block = mongo.db.session_blocks.find_one({"_id": session_obj_id})
        if not session_block:
            return jsonify({"success": False, "message": "Session not found"}), 404

        if session_block["expires_at"] < datetime.utcnow():
            return jsonify({"success": False, "message": "Session expired"}), 401

        hashed_device_id = hashlib.sha256(device_id.encode()).hexdigest()
        if hashed_device_id != session_block["device_id"]:
            return jsonify({"success": False, "message": "Device ID mismatch"}), 401

        logout_exists = mongo.db.session_blocks.find_one({
            "user_email": session_block["user_email"],
            "action": "logout",
            "timestamp": {"$gt": session_block["timestamp"]}
        })
        if logout_exists:
            return jsonify({"success": False, "message": "Session invalid due to logout"}), 401

        # Get user_email from session
        user_email = session_block["user_email"]

        # Generate API key
        api_key = str(uuid.uuid4())

        # Create new API document
        new_api = {
            "user_email": user_email,
            "api_key": api_key,
            "project_name": project_name,
            "domain_allowed": domain_allowed,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        # Insert into UserApis collection
        result = mongo.db.UserApis.insert_one(new_api)
        if not result.inserted_id:
            return jsonify({"success": False, "message": "Failed to create API"}), 500

        # Return success and API data
        return jsonify({
            "success": True,
            "message": "API created successfully",
            "api": {
                "id": str(result.inserted_id),
                "api_key": api_key,
                "project_name": project_name,
                "domain_allowed": domain_allowed,
                "created_at": new_api["created_at"].isoformat(),
                "updated_at": new_api["updated_at"].isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Create API error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/api/user-apis", methods=["GET"])
def get_user_apis():
    try:
        encrypted_session = request.headers.get("X-Encrypted-Session")
        if not encrypted_session:
            return jsonify({"success": False, "message": "Missing X-Encrypted-Session"}), 400

        # Decrypt session data
        session_data = decrypt_data(encrypted_session)
        if not session_data or "session_id" not in session_data or "deviceId" not in session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 400

        session_id = session_data["session_id"]
        device_id = session_data["deviceId"]

        # Verify session
        try:
            session_obj_id = ObjectId(session_id)
        except InvalidId:
            return jsonify({"success": False, "message": "Invalid session_id"}), 400

        session_block = mongo.db.session_blocks.find_one({"_id": session_obj_id})
        if not session_block:
            return jsonify({"success": False, "message": "Session not found"}), 404

        if session_block["expires_at"] < datetime.utcnow():
            return jsonify({"success": False, "message": "Session expired"}), 401

        hashed_device_id = hashlib.sha256(device_id.encode()).hexdigest()
        if hashed_device_id != session_block["device_id"]:
            return jsonify({"success": False, "message": "Device ID mismatch"}), 401

        logout_exists = mongo.db.session_blocks.find_one({
            "user_email": session_block["user_email"],
            "action": "logout",
            "timestamp": {"$gt": session_block["timestamp"]}
        })
        if logout_exists:
            return jsonify({"success": False, "message": "Session invalid due to logout"}), 401

        # Get user_email from session
        user_email = session_block["user_email"]

        # Find all APIs for this user_email
        apis = list(mongo.db.UserApis.find({"user_email": user_email}, {
            "_id": 1,
            "api_key": 1,
            "project_name": 1,
            "domain_allowed": 1,
            "created_at": 1,
            "updated_at": 1
        }))

        # Format the response
        formatted_apis = [
            {
                "id": str(api["_id"]),
                "api_key": api["api_key"],
                "project_name": api["project_name"],
                "domain_allowed": api["domain_allowed"],
                "created_at": api["created_at"].isoformat(),
                "updated_at": api["updated_at"].isoformat()
            } for api in apis
        ]

        return jsonify({
            "success": True,
            "message": "APIs retrieved successfully",
            "apis": formatted_apis
        })

    except Exception as e:
        logger.error(f"Get user APIs error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500
    
CONTACT_COLLECTION = "contact_messages"

@app.route('/api/contact', methods=['POST'])
def contact_us():
    """Handles contact form submissions"""
    try:
        # Get and validate request data
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        # Required fields
        required_fields = ['name', 'email', 'subject', 'message']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Validate email format
        if not EMAIL_REGEX.match(data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Create contact document
        contact_doc = {
            'name': data['name'],
            'email': data['email'],
            'subject': data['subject'],
            'message': data['message'],
            'created_at': datetime.utcnow(),
            'status': 'new',
            'ip_address': request.remote_addr
        }
        
        # Insert into database
        result = mongo.db[CONTACT_COLLECTION].insert_one(contact_doc)
        
        if not result.inserted_id:
            return jsonify({'success': False, 'message': 'Failed to save message'}), 500
        
        # Send confirmation email (optional)
        send_contact_confirmation(data['email'], data['name'])
        
        return jsonify({
            'success': True,
            'message': 'Thank you for contacting us! We\'ll get back to you soon.'
        })
    
    except Exception as e:
        logger.error(f"Contact form error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

def send_contact_confirmation(email, name):
    """Sends confirmation email to user"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Thank You for Contacting ChainID'
        msg['From'] = Config.GMAIL_ADDRESS
        msg['To'] = email
        
        text = f"""\
Hi {name},
        
Thank you for reaching out to us! We've received your message and our team will get back to you soon.
        
Best regards,
The ChainID Team
"""
        
        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #0f0f15; color: #e0e0e0; border-radius: 10px; border: 1px solid #6a11cb;">
      <h2 style="color: #6a11cb; text-align: center;">Thank You for Contacting ChainID</h2>
      <p>Hi {name},</p>
      <p>We've received your message and our team will review it shortly. We typically respond within 24-48 hours.</p>
      <p>If your inquiry is urgent, please feel free to contact us directly at support@chainid.example.com</p>
      <p style="margin-top: 30px;">Best regards,<br>The ChainID Team</p>
      <div style="margin-top: 40px; text-align: center; font-size: 12px; color: #888;">
        <p>This is an automated message. Please do not reply to this email.</p>
      </div>
    </div>
  </body>
</html>
"""
        
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(Config.GMAIL_ADDRESS, Config.GMAIL_APP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Contact confirmation sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send contact confirmation: {str(e)}")

# --- Database Initialization ---
def init_db():
    """Initializes database collections and indexes."""
    logger.info("Initializing database...")
    
    # Create indexes
    mongo.db.session_blocks.create_index("block_index", unique=True)
    mongo.db.session_blocks.create_index("current_hash", unique=True)
    mongo.db.session_blocks.create_index([("user_email", 1), ("timestamp", -1)])
    
    mongo.db.blocks.create_index("index", unique=True)
    mongo.db.blocks.create_index("hash", unique=True)
    
    mongo.db.users.create_index("email", unique=True)
    
    cleanup_expired_sessions()  # Clean up before rebuilding
    rebuild_active_sessions()
    logger.info("Database initialized")

# --- Main ---
if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)