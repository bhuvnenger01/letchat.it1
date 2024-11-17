from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, send
import datetime
import jwt
import bcrypt
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import os

app = Flask(__name__)
app.secret_key = '6737a042b48a581b59cda9e5'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# MongoDB setup
client = MongoClient('mongodb+srv://bhuvicoder01:9806671598@chat-data.lzjht.mongodb.net/',tls=True, tlsAllowInvalidCertificates=True)
db = client['chat-data']
user_collection = db['users']

# Secret key for JWT
JWT_SECRET = '6737a042b48a581b59cda9e6'

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.route('/public-key', methods=['GET'])
def get_public_key():
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({'publicKey': pem_public_key.decode('utf-8')})

# Function to verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload['username']  # Return the username from the payload if valid
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/protected', methods=['GET'])
def protected():
    # Get the token from the Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"message": "Missing or invalid token"}), 401

    token = auth_header.split(' ')[1]  # Extract the token part
    username = verify_token(token)  # Verify the token using the verify_token function

    if not username:
        return jsonify({"message": "Invalid or expired token"}), 401

    return jsonify({"username": username}), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    if user_collection.find_one({'username': username}):
        return jsonify({"message": "Username already exists"}), 400
    
    user_collection.insert_one({'username': username, 'password': hashed_password})
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = user_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        token = jwt.encode(
            {'username': username, 'exp': datetime.now(timezone.utc) + timedelta(days=1)},
            JWT_SECRET,
            algorithm="HS256"
        )
        print("token",token)
        return jsonify({"token": token}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401


@app.route('/chat', methods=['GET'])
def chat():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"message": "Missing or invalid token"}), 401
    token = auth_header.split(' ')[1]  # Extract the token part
    username = verify_token(token)  # Verify the token using the verify_token function
    if not username:
        return jsonify({"message": "Invalid or expired token"}), 401
    
    return jsonify({'message': f'Welcome to the chat, {username}'}), 200  # Chat accessible

# SocketIO events for chat
@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    send(f"{username} has joined the room.", to=room)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(f"{username} has left the room.", to=room)

@socketio.on('message')
def handle_message(data):
    encrypted_message = data['encryptedMessage']
    encrypted_key = data['encryptedKey']

    # Decrypt the AES key with the server's private key
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message with the AES key
    iv = aes_key  # In this example, the IV is the same as the AES key
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(base64.b64decode(encrypted_message)) + decryptor.finalize()

    # Broadcast the decrypted message
    room = data['room']
    send(f"{data['username']}: {decrypted_message.decode('utf-8')}", to=room)


if __name__ == '__main__':
    socketio.run(app, debug=True)
