from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import random
import os
import smtplib
from email.mime.text import MIMEText
import logging
import time
from dotenv import load_dotenv
import re
import json
import hashlib
import numpy as np
import cv2
from deepface import DeepFace
from scipy.spatial.distance import euclidean
from datetime import datetime, timedelta
from sqlalchemy import (
    create_engine, ForeignKey, Column, String, DateTime, Enum, Integer, JSON,
    CheckConstraint, func, Index
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import filetype
import zlib

# --- Configuration ---
class Config:
    """Centralized configuration for the application."""
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "taran")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "4000")
    DB_NAME = os.getenv("DB_NAME", "CHAINID")
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

# --- Database Setup ---
DATABASE_URL = (
    f"mysql+pymysql://{Config.DB_USER}:{Config.DB_PASSWORD}@"
    f"{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}"
)
engine = create_engine(DATABASE_URL, echo=False, future=True)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- Models ---
class User(Base):
    """Stores user information with biometric data."""
    __tablename__ = 'users'

    email = Column(String(255), primary_key=True, nullable=False)
    signup_method = Column(Enum('face', 'fingerprint', 'both', 'none', name='signup_method_enum'), nullable=True)
    face_id = Column(String(2048), nullable=True)
    fingerprint_id = Column(String(255), nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "(signup_method = 'face' AND face_id IS NOT NULL AND fingerprint_id IS NULL) OR "
            "(signup_method = 'fingerprint' AND fingerprint_id IS NOT NULL AND face_id IS NULL) OR "
            "(signup_method = 'both' AND face_id IS NOT NULL AND fingerprint_id IS NOT NULL) OR "
            "(signup_method = 'none' AND face_id IS NULL AND fingerprint_id IS NULL) OR "
            "signup_method IS NULL",
            name='valid_signup_method_check'
        ),
    )

class SessionBlock(Base):
    """Stores blockchain-based session data with performance indices."""
    __tablename__ = 'session_blocks'

    id = Column(Integer, primary_key=True, autoincrement=True)
    block_index = Column(Integer, nullable=False, unique=True)
    user_email = Column(String(255), ForeignKey('users.email'), nullable=False)
    signup_method = Column(String(20), nullable=False)
    device_id = Column(String(64), nullable=False)
    action = Column(Enum('login', 'logout', 'renew'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), unique=True, nullable=False)
    nonce = Column(Integer, nullable=False)

    __table_args__ = (
        CheckConstraint("expires_at > timestamp", name='valid_expiry_time'),
        CheckConstraint("signup_method IN ('face', 'fingerprint', 'both', 'none')", name='valid_signup_method'),
        Index('idx_user_email_timestamp', 'user_email', 'timestamp'),
    )

class BlockModel(Base):
    """Stores general blockchain data."""
    __tablename__ = 'blocks'

    id = Column(Integer, primary_key=True, autoincrement=True)
    index = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    data = Column(JSON, nullable=False)
    previous_hash = Column(String(255))
    hash = Column(String(255), unique=True, nullable=False)

# --- Blockchain Classes ---
class Block:
    """Represents a single block in the main blockchain."""
    def __init__(self, index, timestamp, data, previous_hash=''):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates SHA-256 hash of block data."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

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
            bool: True if block creation succeeds, False otherwise
        """
        session = SessionLocal()
        try:
            last_block = session.query(SessionBlock).order_by(SessionBlock.block_index.desc()).first()
            new_index = last_block.block_index + 1 if last_block else 0
            self.logger.info(f"Creating session block #{new_index} for {user_email}")

            # Truncate microseconds to ensure database consistency
            current_time = datetime.utcnow().replace(microsecond=0)
            expires_at = current_time + self.session_expiry

            new_block = {
                'block_index': new_index,
                'user_email': user_email,
                'signup_method': signup_method,
                'device_id': hashlib.sha256(device_id.encode()).hexdigest(),
                'action': action,
                'timestamp': current_time,  # Use truncated time
                'expires_at': expires_at,   # Use truncated time for consistency
                'previous_hash': last_block.current_hash if last_block else '0',
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

            # Store block in database
            session_block = SessionBlock(**new_block)
            session.add(session_block)
            session.commit()
            self.logger.info(f"Session block #{new_index} saved")
            return new_block 

        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to create session block: {str(e)}")
            return False
        finally:
            session.close()

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
        session = SessionLocal()
        try:
            blocks = session.query(SessionBlock).order_by(SessionBlock.block_index).all()
            for i in range(1, len(blocks)):
                curr = blocks[i]
                prev = blocks[i - 1]
                if curr.previous_hash != prev.current_hash:
                    return False, f"Chain broken at index {curr.block_index}"
                if not curr.current_hash.startswith('0' * self.difficulty):
                    return False, f"Invalid PoW at index {curr.block_index}"
                # Recalculate hash
                computed_hash = self._calculate_hash({
                    'block_index': curr.block_index,
                    'user_email': curr.user_email,
                    'signup_method': curr.signup_method,
                    'device_id': curr.device_id,
                    'action': curr.action,
                    'timestamp': curr.timestamp,
                    'expires_at': curr.expires_at,
                    'previous_hash': curr.previous_hash,
                    'nonce': curr.nonce
                })
                if computed_hash != curr.current_hash:
                    return False, f"Hash mismatch at index {curr.block_index}"
            return True, None
        except SQLAlchemyError as e:
            self.logger.error(f"Chain validation failed: {str(e)}")
            return False, "Validation error"
        finally:
            session.close()

# --- In-memory Blockchain ---
blockchain = []

def add_block(data_dict):
    """
    Adds a new block to the main blockchain.

    Args:
        data_dict (dict): Block data to store

    Returns:
        Block: Newly created block or None if failed
    """
    session = SessionLocal()
    try:
        prev_block = blockchain[-1] if blockchain else None
        new_block = Block(
            index=len(blockchain),
            timestamp=datetime.utcnow(),
            data=data_dict,
            previous_hash=prev_block.hash if prev_block else '0'
        )
        blockchain.append(new_block)

        db_block = BlockModel(
            index=new_block.index,
            timestamp=new_block.timestamp,
            data=new_block.data,
            previous_hash=new_block.previous_hash,
            hash=new_block.hash
        )
        session.add(db_block)
        session.commit()
        logging.info(f"Block #{new_block.index} added")
        return new_block
    except SQLAlchemyError as e:
        session.rollback()
        logging.error(f"Failed to add block: {str(e)}")
        return None
    finally:
        session.close()

# --- Session Management ---
active_sessions = {}

def rebuild_active_sessions():
    """
    Rebuilds active sessions from session blockchain on startup.
    """
    session = SessionLocal()
    try:
        active_sessions.clear()
        valid_logins = session.query(SessionBlock).filter(
            SessionBlock.action == 'login',
            SessionBlock.expires_at > datetime.utcnow()
        ).order_by(SessionBlock.timestamp.desc()).all()

        for login in valid_logins:
            logout_exists = session.query(SessionBlock).filter(
                SessionBlock.user_email == login.user_email,
                SessionBlock.action == 'logout',
                SessionBlock.timestamp > login.timestamp
            ).first()

            if not logout_exists:
                active_sessions[login.user_email] = {
                    'device_id': login.device_id,
                    'expires': login.expires_at
                }
        logging.info(f"Rebuilt {len(active_sessions)} active sessions")
    except SQLAlchemyError as e:
        logging.error(f"Session rebuild failed: {str(e)}")
    finally:
        session.close()

def cleanup_expired_sessions():
    """
    Removes expired sessions from database and cache.
    """
    session = SessionLocal()
    try:
        deleted = session.query(SessionBlock).filter(
            SessionBlock.expires_at < datetime.utcnow()
        ).delete()
        session.commit()
        logging.info(f"Cleaned up {deleted} expired session blocks")
        active_sessions.clear()
        rebuild_active_sessions()
    except SQLAlchemyError as e:
        logging.error(f"Session cleanup failed: {str(e)}")
    finally:
        session.close()

# --- Flask Setup ---
app = Flask(__name__)
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
    session = SessionLocal()
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
        initialize_genesis_block(session)

        # Validate blockchain
        blocks = session.query(BlockModel).order_by(BlockModel.index.asc()).all()
        is_valid, error_msg = is_blockchain_valid(blocks)
        if not is_valid:
            app.logger.error(f"Blockchain validation failed: {error_msg}")
            return jsonify({"success": False, "message": f"Blockchain invalid: {error_msg}"}), 400

        # Check if email is already registered in the blockchain
        for blk in blocks:
            try:
                # Check email existence based on purpose
                if purpose == 'signup':
                    # Check blockchain/users table for existing email (prevent duplicates)
                    user_exists = session.query(User).filter_by(email=email).first()
                    if user_exists:
                        return jsonify({"success": False, "message": "Email already registered"}), 400
                elif purpose == 'login':
                    # Ensure email exists in users table
                    user = session.query(User).filter_by(email=email).first()
                    if not user:
                        return jsonify({"success": False, "message": "Email not found. Please sign up."}), 404
            except json.JSONDecodeError:
                app.logger.warning(f"Invalid JSON in block {blk.index}, skipping")
                continue

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
    finally:
        session.close()

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
    session = SessionLocal()
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

        # Recalculate method securely
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
        user = User(
            email=email,
            signup_method=None if signup_method == 'none' else signup_method,
            face_id=face_data if signup_method in ['face', 'both'] else None,
            fingerprint_id=fingerprint_data if signup_method in ['fingerprint', 'both'] else None
        )
        session.add(user)
        session.commit()

        # Create session block
        session_block = chain.create_session_block(email, signup_method, device_id, 'login')
        if not session_block:
            raise Exception("Failed to create session block")

        if not session_block:
            raise Exception("Failed to retrieve session block for linking")
        
        print(session_block)

        # Add to blockchain
        add_block({
            "email": email,
            "device_id": device_id,
            'face_id':face_data if signup_method in ['face', 'both'] else None,
            'fingerprint_id':fingerprint_data if signup_method in ['fingerprint', 'both'] else None,
            "session_block_id":session_block['current_hash'],   
        })

        # Add to active sessions
        active_sessions[email] = {
            "device_id": device_id,
            "expires": datetime.utcnow() + Config.SESSION_DURATION
        }

        # Email content (unchanged)
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

        return jsonify({"success": True, "message": "Registration successful"})

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"success": False, "message": "Database error"}), 500
    except Exception as e:
        session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"success": False, "message": "Registration failed"}), 500
    finally:
        session.close()


@app.route("/api/login", methods=["POST"])
def login():
    """Logs in a user and creates session-only blockchain entry."""
    session = SessionLocal()
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
            return jsonify({"success": False, "message": "Invalid device ID format"}), 400

        # Check user exists
        user = session.query(User).filter_by(email=email).first()
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
            raise Exception("Failed to retrieve session block for linking")

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
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
                  <p style="margin: 5px 0;">
                    <strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                  </p>
                  <p style="margin: 5px 0;">
                    <strong>Device ID:</strong> {device_id}
                  </p>
                </div>
                <p style="color: #dc3545; margin-top: 15px;">
                  If this wasn't you, please contact our 
                  <a href="mailto:support@chainid.example.com" style="color: #007bff;">
                    support team
                  </a> immediately.
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
                logger.info(f"Login notification sent to {email}")
        except smtplib.SMTPException as e:
            logger.error(f"Failed to send login email: {str(e)}")

        return jsonify({"success": True, "message": "Login successful"})

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error during login: {str(e)}")
        return jsonify({"success": False, "message": "Database error"}), 500
    except Exception as e:
        session.rollback()
        logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "message": "Login failed"}), 500
    finally:
        session.close()

# --- File Uploads ---
@app.route('/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    image_file = request.files['image']
    email = request.form.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Check image type
    kind = filetype.guess(image_file.stream.read(261))
    image_file.stream.seek(0)
    if not kind or kind.extension not in ['jpg', 'jpeg', 'png']:
        return jsonify({"error": "Invalid image format. Only JPG and PNG are allowed"}), 400

    try:
        image_bytes = image_file.read()
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)  # Decode as BGR color

        if img is None:
            return jsonify({"error": "Invalid image content"}), 400

        # Log image details for debugging
        logger.info(f"Image shape: {img.shape}, dtype: {img.dtype}")

        # Ensure image is 8-bit (uint8)
        if img.dtype != np.uint8:
            logger.warning(f"Converting image from {img.dtype} to uint8")
            img = img.astype(np.uint8)

        # Convert BGR to RGB
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        # Verify RGB image format
        if len(img_rgb.shape) != 3 or img_rgb.shape[2] != 3:
            return jsonify({"error": "Image must be RGB"}), 400

        # Use DeepFace to represent the face
        try:
            result = DeepFace.represent(
                img_path=img_rgb,
                model_name="Facenet",
                detector_backend="opencv",
                enforce_detection=True
            )
            if len(result) == 0:
                return jsonify({"message": "No face found", "id": 0}), 400
            embedding = result[0]["embedding"]
            # Convert to float32 for consistency and efficiency
            embedding_array = np.array(embedding, dtype=np.float32)
            if embedding_array.shape[0] != 128:
                logger.error(f"Unexpected embedding dimension: {embedding_array.shape[0]}")
                return jsonify({"error": "Invalid embedding dimension"}), 500
            compressed_embedding = zlib.compress(embedding_array.tobytes())
            face_data = base64.b64encode(compressed_embedding).decode('utf-8')
        except Exception as e:
            logger.error(f"Face encoding failed: {str(e)}")
            return jsonify({"error": f"Face encoding failed: {str(e)}"}), 500

        return jsonify({
            "message": "Face detected and encoded successfully",
            "faceData": face_data,
            "email": email
        }), 200

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/login-face", methods=["POST"])
def login_face():
    session = SessionLocal()
    try:
        # 1. Parse and validate request
        data = request.get_json()
        if not data or "encryptedSession" not in data:
            return jsonify({"success": False, "message": "Missing session data"}), 400

        # 2. Decrypt session data
        session_data = decrypt_data(data["encryptedSession"])
        if not session_data or "email" not in session_data or "deviceId" not in session_data or "image" not in session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 400

        email = session_data["email"]
        device_id = session_data["deviceId"]
        image_base64 = session_data["image"]

        # 3. Validate device ID format
        if not DEVICE_ID_REGEX.match(device_id):
            return jsonify({"success": False, "message": "Invalid device ID format"}), 400

        # 4. Decode base64 image
        try:
            if "," in image_base64:
                image_base64 = image_base64.split(",")[1]
            image_bytes = base64.b64decode(image_base64)
            np_arr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if img is None:
                return jsonify({"success": False, "message": "Invalid image content"}), 400
        except Exception as e:
            logger.error(f"Image processing error: {str(e)}")
            return jsonify({"success": False, "message": "Invalid image format"}), 400

        # Log image details for debugging
        logger.info(f"Image shape: {img.shape}, dtype: {img.dtype}")

        # Ensure image is 8-bit (uint8)
        if img.dtype != np.uint8:
            logger.warning(f"Converting image from {img.dtype} to uint8")
            img = img.astype(np.uint8)

        # Convert BGR to RGB
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        # Verify RGB image format
        if len(img_rgb.shape) != 3 or img_rgb.shape[2] != 3:
            return jsonify({"success": False, "message": "Image must be RGB"}), 400

        # 6. Use DeepFace to represent the current face
        try:
            result = DeepFace.represent(
                img_path=img_rgb,
                model_name="Facenet",
                detector_backend="opencv",
                enforce_detection=True
            )
            if len(result) == 0:
                return jsonify({"success": False, "message": "No face detected"}), 400
            current_embedding = np.array(result[0]["embedding"], dtype=np.float32)
            if current_embedding.shape[0] != 128:
                logger.error(f"Unexpected current embedding dimension: {current_embedding.shape[0]}")
                return jsonify({"success": False, "message": "Invalid embedding dimension"}), 500
        except Exception as e:
            logger.error(f"Face encoding failed: {str(e)}")
            return jsonify({"success": False, "message": f"Face encoding failed: {str(e)}"}), 500

        # 7. Retrieve user
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        if not user.face_id or user.signup_method not in ['face', 'both']:
            return jsonify({"success": False, "message": "Face login not enabled for this account"}), 403

        # 8. Decode stored face encoding
        try:
            compressed_embedding = base64.b64decode(user.face_id)
            decompressed_embedding = zlib.decompress(compressed_embedding)
            stored_embedding = np.frombuffer(decompressed_embedding, dtype=np.float32)
            if stored_embedding.shape[0] != 128:
                logger.error(f"Unexpected stored embedding dimension: {stored_embedding.shape[0]}")
                return jsonify({"success": False, "message": "Corrupted face data"}), 500
        except Exception as e:
            logger.error(f"Failed to decode/decompress stored face encoding: {str(e)}")
            return jsonify({"success": False, "message": "Corrupted face data"}), 500

        # 9. Compare embeddings using Euclidean distance
        distance = euclidean(current_embedding, stored_embedding)
        logger.info(f"Face verification for {email}: Euclidean distance = {distance}")
        if distance > 5:  # Threshold for Facenet with opencv backend
            logger.warning(f"Face login failed for {email}, distance: {distance}")
            return jsonify({"success": False, "message": "Face verification failed"}), 401

        # 10. Validate blockchain
        chain = SessionBlockChain()
        is_valid, error_msg = chain.validate_chain()
        if not is_valid:
            return jsonify({"success": False, "message": f"Session blockchain error: {error_msg}"}), 400

        # 11. Create session block
        session_block = chain.create_session_block(email, 'face', device_id, 'login')
        if not session_block:
            raise Exception("Failed to create session block")

        # 12. Update active session tracking
        active_sessions[email] = {
            "device_id": device_id,
            "expires": datetime.utcnow() + Config.SESSION_DURATION
        }

        # 13. Send login notification
        send_login_notification(email, device_id, "face")

        return jsonify({
            "success": True,
            "message": "Face login successful",
            "session_block": session_block['current_hash']
        })

    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error during face login: {str(e)}")
        return jsonify({"success": False, "message": "Database error"}), 500
    except Exception as e:
        session.rollback()
        logger.error(f"Face login error: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500
    finally:
        session.close()
        
def compare_face_hashes(stored_hash, current_hash, threshold=0.9):
    """
    Compares face hashes with some tolerance for minor variations.
    In a real implementation, you'd use a proper facial recognition library.
    This is a simplified version using exact matching.
    """
    return stored_hash == current_hash

def send_login_notification(email, device_id, method):
    """Sends login notification email"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'ChainID - Successful {method.capitalize()} Login'
        msg['From'] = Config.GMAIL_ADDRESS
        msg['To'] = email

        text = f"""\
Hello,

You've successfully logged in to your ChainID account using {method} recognition.

Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Device ID: {device_id}

If this wasn't you, please contact our support team immediately.

Best regards,
The ChainID Team
"""

        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <h3 style="color: #007bff;">Successful {method.capitalize()} Login</h3>
    <p>Hello,</p>
    <p>You've successfully logged in to your ChainID account using {method} recognition.</p>
    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
      <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
      <p><strong>Device ID:</strong> {device_id}</p>
    </div>
    <p style="color: #dc3545;">
      If this wasn't you, please contact our 
      <a href="mailto:support@chainid.example.com" style="color: #007bff;">
        support team
      </a> immediately.
    </p>
  </body>
</html>
"""

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(Config.GMAIL_ADDRESS, Config.GMAIL_APP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Login notification sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send login email: {str(e)}")

@app.route("/api/get-fingerprint-id", methods=["POST"])
def get_fingerprint_id():
    """Retrieves the fingerprint ID associated with the given email."""
    session = SessionLocal()
    try:
        # Get and validate request data
        data = request.get_json()
        if not data or 'encrypted_email' not in data:
            return jsonify({"success": False, "message": "Missing encrypted_email"}), 400

        # Decrypt email
        email_data = decrypt_data(data['encrypted_email'])
        if not email_data or 'email' not in email_data or not EMAIL_REGEX.match(email_data['email']):
            return jsonify({"success": False, "message": "Invalid email"}), 400
        
        email = email_data['email']
        
        # Query database for user
        user = session.query(User).filter_by(email=email).first()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        # Check if fingerprint is registered
        if not user.fingerprint_id or user.signup_method not in ['fingerprint', 'both']:
            return jsonify({"success": False, "message": "Fingerprint not registered"}), 404

        print("Fingerprint ID :",user.fingerprint_id)

        # Return fingerprint ID directly (not encrypted)
        return jsonify({
            "success": True,
            "fingerprint_id": user.fingerprint_id,
            "message": "Fingerprint ID retrieved"
        })

    except Exception as e:
        logger.error(f"Error retrieving fingerprint ID: {str(e)}")
        return jsonify({"success": False, "message": "Server error"}), 500
    finally:
        session.close()

@app.route("/api/login-fingerprint", methods=["POST"])
def login_fingerprint():
    session = SessionLocal()
    try:
        # 1) Pull and decrypt
        payload = request.get_json() or {}
        encrypted = payload.get("encryptedSession")
        if not encrypted:
            return jsonify(success=False, message="Missing session data"), 400

        session_data = decrypt_data(encrypted)
        if not session_data:
            return jsonify(success=False, message="Invalid session data"), 400

        email     = session_data.get("email")
        public_key= session_data.get("publicKey")
        device_id = session_data.get("deviceId")

        print("Device ID :",device_id)
        print("Public Key :",public_key)
        print("Email :",email)

        if not email or not public_key or not device_id:
            return jsonify(success=False, message="Incomplete session data"), 400

        # 2) Basic checks
        if not DEVICE_ID_REGEX.match(device_id):
            return jsonify(success=False, message="Invalid device ID format"), 400

        user = session.query(User).filter_by(email=email).first()
        if not user:
            return jsonify(success=False, message="User not found"), 404

        if user.signup_method not in ("fingerprint", "both") or not user.fingerprint_id:
            return jsonify(success=False, message="Fingerprint login not enabled"), 403

        # 3) Verify fingerprint by direct match
        if public_key != user.fingerprint_id:
            return jsonify(success=False, message="Fingerprint verification failed"), 401

        # 4) Validate blockchain integrity
        chain = SessionBlockChain()
        is_valid, err = chain.validate_chain()
        if not is_valid:
            return jsonify(success=False, message=f"Blockchain invalid: {err}"), 400

        # 5) Create session block
        block = chain.create_session_block(email, "fingerprint", device_id, "login")
        if not block:
            raise Exception("Failed to create session block")

        # 6) Track active session
        active_sessions[email] = {
            "device_id": device_id,
            "expires": datetime.utcnow() + Config.SESSION_DURATION
        }

        # 7) Send login notification email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "ChainID – Successful Fingerprint Login"
        msg["From"]    = app.config["GMAIL_ADDRESS"]
        msg["To"]      = email

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        text = f"""\
Hello,

Your ChainID account was accessed via fingerprint login.

Time: {timestamp}
Device ID: {device_id}

If this wasn’t you, contact support immediately.

– ChainID Team
"""
        html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; color: #333;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr><td align="center">
        <table width="600" cellpadding="20" cellspacing="0" style="border:1px solid #ddd;">
          <tr><td>
            <h3 style="color:#007bff;">Fingerprint Login Alert</h3>
            <p>Hello,</p>
            <p>Your ChainID account was accessed via fingerprint login.</p>
            <div style="background:#f8f9fa;padding:15px;border-radius:5px;">
              <p><strong>Time:</strong> {timestamp}</p>
              <p><strong>Device ID:</strong> {device_id}</p>
            </div>
            <p style="color:#dc3545;">If this wasn’t you, please contact our 
               <a href="mailto:support@chainid.example.com" style="color:#007bff;">
               support team</a> immediately.</p>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>
"""
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(app.config["GMAIL_ADDRESS"], app.config["GMAIL_APP_PASSWORD"])
                s.send_message(msg)
                logger.info(f"Login notification sent to {email}")
        except Exception as mail_err:
            logger.error(f"Failed to send login email: {mail_err}")

        return jsonify(success=True, message="Fingerprint login successful"), 200

    except SQLAlchemyError as db_err:
        session.rollback()
        logger.error(f"DB error during fingerprint login: {db_err}")
        return jsonify(success=False, message="Database error"), 500

    except Exception as e:
        session.rollback()
        logger.error(f"Fingerprint login error: {e}")
        return jsonify(success=False, message="Server error"), 500

    finally:
        session.close()

@app.route("/api/verify-session", methods=["POST"])
def verify_session():
    """Verifies session using session blockchain."""
    try:
        data = request.get_json()
        encrypted = data.get("encryptedSession")

        session_data = decrypt_data(encrypted)
        if not session_data:
            return jsonify({"success": False, "message": "Invalid session data"}), 401

        email = session_data.get("email")
        device_id = session_data.get("deviceId")
        if not DEVICE_ID_REGEX.match(device_id):
            return jsonify({"success": False, "message": "Invalid device ID format"}), 400

        # Check active sessions cache
        session_info = active_sessions.get(email)
        if session_info and session_info["device_id"] == device_id and datetime.utcnow() < session_info["expires"]:
            return jsonify({"success": True, "message": "Session valid"})

        # Verify using session blockchain
        session = SessionLocal()
        try:
            valid_login = session.query(SessionBlock).filter(
                SessionBlock.user_email == email,
                SessionBlock.device_id == hashlib.sha256(device_id.encode()).hexdigest(),
                SessionBlock.action == 'login',
                SessionBlock.expires_at > datetime.utcnow()
            ).order_by(SessionBlock.timestamp.desc()).first()

            if valid_login:
                # Check for logout
                logout_exists = session.query(SessionBlock).filter(
                    SessionBlock.user_email == email,
                    SessionBlock.action == 'logout',
                    SessionBlock.timestamp > valid_login.timestamp
                ).first()

                if not logout_exists:
                    # Update cache
                    active_sessions[email] = {
                        "device_id": device_id,
                        "expires": valid_login.expires_at
                    }
                    return jsonify({"success": True, "message": "Session valid"})

            return jsonify({"success": False, "message": "No valid session"}), 401

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Session verification error: {str(e)}")
        return jsonify({"success": False, "message": "Verification failed"}), 500

def is_blockchain_valid(blocks):
    """Validates the blockchain integrity."""
    if not blocks:
        return False, "Blockchain is empty"
    
    # Validate genesis block
    genesis = blocks[0]
    if genesis.index != 0 or genesis.previous_hash != '0':
        return False, "Invalid genesis block"
    
    # Validate chain integrity
    for i in range(1, len(blocks)):
        current = blocks[i]
        previous = blocks[i - 1]
        if current.previous_hash != previous.hash:
            return False, f"Broken link at block index {current.index}"
    
    return True, None

# Function to ensure a genesis block exists
def initialize_genesis_block(session):
    """Ensures a genesis block exists in the blockchain."""
    genesis_exists = session.query(BlockModel).filter_by(index=0).first()
    if not genesis_exists:
        genesis_block = BlockModel(
            index=0,
            timestamp=datetime.utcnow(),
            data=json.dumps({"type": "genesis"}),  # Store as JSON string
            previous_hash='0',
            hash='0'  # Consider computing a real hash for production
        )
        session.add(genesis_block)
        session.commit()
        app.logger.info("Genesis block created successfully")

@app.route("/api/check-email", methods=["POST", "OPTIONS"])
def check_email():
    if request.method == "OPTIONS":
        # Handle preflight request
        response = jsonify({"success": True})
        response.headers.add("Access-Control-Allow-Origin", Config.ALLOWED_ORIGINS)
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST")
        return response

    try:
        logger.info("Received check-email request")
        
        # Validate content type
        if not request.is_json:
            logger.warning("Invalid content type")
            return jsonify({
                "success": False,
                "message": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            logger.warning("No JSON data received")
            return jsonify({
                "success": False,
                "message": "No data received"
            }), 400

        encrypted_email = data.get("encrypted_email")
        if not encrypted_email:
            logger.warning("Missing encrypted_email parameter")
            return jsonify({
                "success": False,
                "message": "encrypted_email is required"
            }), 400

        # Decrypt the email
        try:
            decrypted = decrypt_data(encrypted_email)
            if not decrypted or not isinstance(decrypted, dict) or 'email' not in decrypted:
                logger.error("Decrypted data missing email field")
                return jsonify({
                    "success": False,
                    "message": "Invalid decrypted data format"
                }), 400
                
            email = decrypted['email'].strip().lower()
            logger.info(f"Processing email: {email}")
            
            if not EMAIL_REGEX.match(email):
                logger.warning(f"Invalid email format: {email}")
                return jsonify({
                    "success": False,
                    "message": "Invalid email format"
                }), 400
                
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Email decryption failed"
            }), 400

        session = None
        try:
            session = SessionLocal()
            logger.info("Database session created")

            # First check in users table (faster primary key lookup)
            user = session.query(User).filter_by(email=email).first()
            if user:
                logger.info(f"Email found in users table: {email}")
                return jsonify({
                    "success": True,
                    "email": email,
                    "signup_method": user.signup_method,
                    "exists": True
                }), 200

            # Check blockchain if not found in users table
            logger.info(f"Checking blockchain for email: {email}")
            blocks = session.query(BlockModel).order_by(BlockModel.index.asc()).all()
            
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
                        block_data = block.data
                        
                        # Handle potential double JSON encoding
                        if isinstance(block_data, str):
                            try:
                                block_data = json.loads(block_data)
                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse block data for block {block.index}")
                                continue
                        
                        # Get and compare email
                        stored_email = block_data.get('email', '').strip().lower()
                        if stored_email == email:
                            logger.info(f"Email found in blockchain block {block.index}")
                            return jsonify({
                                "success": True,
                                "email": email,
                                "signup_method": None,
                                "exists": True,
                                "message": "Found in blockchain but not in users table"
                            }), 200
                            
                    except Exception as e:
                        logger.error(f"Error processing block {block.index}: {str(e)}")
                        continue

            # Email not found anywhere
            logger.info(f"Email not found: {email}")
            return jsonify({
                "success": True,
                "email": email,
                "signup_method": None,
                "exists": False
            }), 200

        except SQLAlchemyError as e:
            logger.error(f"Database error: {str(e)}")
            if session:
                session.rollback()
            return jsonify({
                "success": False,
                "message": "Database operation failed"
            }), 500
        finally:
            if session:
                session.close()
                logger.info("Database session closed")

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Internal server error"
        }), 500

# --- Database Initialization ---
def init_db():
    """Initializes database tables and rebuilds active sessions."""
    logger.info("Initializing database...")
    Base.metadata.create_all(bind=engine)
    cleanup_expired_sessions()  # Clean up before rebuilding
    rebuild_active_sessions()
    logger.info("Database initialized")

# --- Main ---
if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)