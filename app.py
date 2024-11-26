from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import datetime
import base64

# Flask app setup
app = Flask(__name__)
app.secret_key = '6737a042b48a581b59cda9e5'
app.config['JWT_SECRET_KEY'] = '6737a042b48a581b59cda9e6'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=60)  # Tokens expire in 60 minutes
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True,)
socketio = SocketIO(app, cors_allowed_origins="*")

# MongoDB setup
client = MongoClient('mongodb+srv://bhuvicoder01:9806671598@chat-data.lzjht.mongodb.net/', tls=True, tlsAllowInvalidCertificates=True)
db = client['chat-data']
user_collection = db['users']
message_collection = db['messages']

# JWT Manager
jwt = JWTManager(app)

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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    if user_collection.find_one({'username': username}):
        return jsonify({"message": "Username already exists"}), 400
    
    user_collection.insert_one({'username': username, 'password': hashed_password})
    return jsonify({"message": "User  registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = user_collection.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        access_token = create_access_token(identity=username)
        return jsonify({"token": access_token}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    username = get_jwt_identity()  # Extract username from the token
    return jsonify({"username": username}), 200

@app.route('/chat', methods=['GET'])
@jwt_required()
def chat():
    username = get_jwt_identity()
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
    message = data['message']  # Receive plaintext message
    room = data['room']
    username = data['username']
    
    # Generate an AES key
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # Initialization vector for AES

    # Encrypt the message using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message.ljust((len(message) + 15) // 16 * 16)  # Pad message to be multiple of 16 bytes
    encrypted_message = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()

    # Encrypt the AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Store the encrypted message and the encrypted AES key in MongoDB
    message_collection.insert_one({
        'room': room,
        'username': username,
        'message': base64.b64encode(encrypted_message).decode('utf-8'),
        'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'timestamp': datetime.datetime.utcnow()
    })

    # Broadcast the plaintext message
    send(f"{username}: {message}", to=room)

@app.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    username = get_jwt_identity()
    messages = message_collection.find({'username': username})
    decrypted_messages = []

    for msg in messages:
        # Decrypt the AES key using the user's private key
        encrypted_aes_key = base64.b64decode(msg['aes_key'])
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the message using AES
        iv = base64.b64decode(msg['iv'])
        encrypted_message = base64.b64decode(msg['message'])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        decrypted_messages.append(decrypted_message.decode('utf-8').strip())

    return jsonify(decrypted_messages), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host="0.0.0.0", debug=True, port=port)