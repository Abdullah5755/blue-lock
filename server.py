import os
import urllib.request
import ipfshttpclient
from flask_session import Session
from my_constants import app
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify
from flask_socketio import SocketIO, send, emit
from werkzeug.utils import secure_filename
import socket
import pickle
from blockchain import Blockchain
import requests
from flask import session # Add this at the top
from flask import request  # Rename import
from werkzeug.security import check_password_hash
from auth import auth as auth_blueprint
from flask_sqlalchemy import SQLAlchemy
from database import db, DownloadRequest
from flask import get_flashed_messages
from datetime import datetime

app = Flask(__name__, static_folder='static')

app.config['BUFFER_SIZE'] = 64 * 1024  # 64KB buffer size
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()
    pending_requests = DownloadRequest.query.filter_by(status="Pending").all()
    print("DEBUG: Pending Requests in DB:", pending_requests)  


# Get absolute path for the upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'upload')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = 'downloads'
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.secret_key = 'your_very_secret_key'  # Change this to a strong random key
app.config['SESSION_TYPE'] = 'filesystem'  # Store session on disk
app.config['SESSION_PERMANENT'] = False  # Don't make session last forever
app.config['SESSION_USE_SIGNER'] = True  # Protect session data
app.config['SESSION_KEY_PREFIX'] = 'blockchain_'  # Prefix session keys
Session(app)  # Initialize session
app.register_blueprint(auth_blueprint, url_prefix='/auth')
socketio = SocketIO(app)
blockchain = Blockchain()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    encrypted_file = file_path + ".aes"
    os.rename(file_path, encrypted_file)
    pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])
    os.remove(file_path)
def hash_user_file(user_file, file_key):
    print("DEBUG: Encrypting file:", user_file)
    encrypt_file(user_file, file_key)
    encrypted_file_path = user_file + ".aes"
    print("DEBUG: Connecting to IPFS...")
    client = ipfshttpclient.connect('/dns4/ipfs.infura.io/tcp/5001/https')
    print("DEBUG: Uploading file to IPFS:", encrypted_file_path)
    response = client.add(encrypted_file_path)
    print("DEBUG: IPFS Response:", response)
    file_hash = response['Hash']
    print("DEBUG: File successfully added to IPFS with hash:", file_hash)
    return file_hash

def retrieve_from_hash(file_hash, file_key):
    client = ipfshttpclient.connect('/dns4/ipfs.infura.io/tcp/5001/https')
    file_content = client.cat(file_hash)
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    user_file = open(file_path, 'ab+')
    user_file.write(file_content)
    user_file.close()
    decrypt_file(file_path, file_key)
    with open(file_path, 'rb') as f:
        lines = f.read().splitlines()
        last_line = lines[-1]
    user_file.close()
    file_extension = last_line
    saved_file = file_path + '.' + file_extension.decode()
    os.rename(file_path, saved_file)
    print(saved_file)
    return saved_file

def get_unique_flashed_messages():
    """Remove duplicate flash messages."""
    messages = get_flashed_messages(with_categories=True)
    unique_messages = list(dict.fromkeys(messages)) 
    return unique_messages

@app.before_request
def check_authentication():
    allowed_routes = ['auth.login', 'auth.register', 'static', 'get_chain']

    print("Session Data:", dict(session))  

    if request.endpoint == 'auth.login' and session.get('username'):
        return redirect(url_for('home'))  

    if not session.get('username') and request.endpoint not in allowed_routes:
        return redirect(url_for('auth.login'))

@app.route('/blockchain_activity')
def blockchain_activity():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))

    blockchain_logs = blockchain.chain  

    return render_template('blockchain_activity.html', blockchain_logs=blockchain_logs)

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):  # Use hash check
        flash("Invalid credentials. Please try again.", "danger")
        return redirect(url_for('auth.login'))
    session['username'] = user.username
    session['role'] = user.role
    flash("✅ Login successful!", "success")  # ✅ Use flash instead of session
    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('index'))
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('index.html')


@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/upload')
def upload():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    return render_template('upload.html')

@app.route('/download')
def download():
    return render_template('download.html')

@app.route('/connect_blockchain')
def connect_blockchain():
    is_chain_replaced = blockchain.replace_chain()
    return render_template('connect_blockchain.html', chain = blockchain.chain, nodes = len(blockchain.nodes))
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))

    # Get pending requests (only "Pending" status)
    pending_requests = DownloadRequest.query.filter_by(status="Pending").all()
    
    # Get past requests (anything NOT "Pending") sorted by latest
    logs = DownloadRequest.query.filter(DownloadRequest.status != "Pending").order_by(DownloadRequest.timestamp.desc()).all()

    print("DEBUG: Showing pending requests:", pending_requests)
    print("DEBUG: Showing logs:", logs)

    return render_template('admin_dashboard.html', requests=pending_requests, logs=logs)




@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))

    request_entry = DownloadRequest.query.get(request_id)
    if request_entry:
        request_entry.status = "Approved"
        request_entry.timestamp = datetime.utcnow()  # ✅ Update Timestamp
        db.session.commit()
        flash("✅ Request approved!", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('auth.login'))

    request_entry = DownloadRequest.query.get(request_id)
    if request_entry:
        request_entry.status = "Rejected"
        request_entry.timestamp = datetime.utcnow()  # ✅ Update Timestamp
        db.session.commit()
        flash("❌ Request rejected! The user can try again.", "danger")

    return redirect(url_for('admin_dashboard'))



@app.errorhandler(413)
def entity_too_large(e):
    return render_template('upload.html' , message = "Requested Entity Too Large!")

@app.route('/add_file', methods=['POST'])
def add_file():
    
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        print('The nodes had different chains so the chain was replaced by the longest one.')
    else:
        print('All good. The chain is the largest one.')

    if request.method == 'POST':
        error_flag = True
        if 'file' not in request.files:
            message = 'No file part'
        else:
            user_file = request.files['file']
            if user_file.filename == '':
                message = 'No file selected for uploading'

            if user_file and allowed_file(user_file.filename):
                error_flag = False
                filename = secure_filename(user_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                user_file.save(file_path)
                append_file_extension(user_file, file_path)
                sender = request.form['sender_name']
                receiver = request.form['receiver_name']
                file_key = request.form['file_key']

                try:
                    hashed_output1 = hash_user_file(file_path, file_key)
                    index = blockchain.add_file(sender, receiver, hashed_output1)
                except Exception as err:
                    message = str(err)
                    error_flag = True
                    if "ConnectionError:" in message:
                        message = "Gateway down or bad Internet!"

            else:
                error_flag = True
                message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
    
        if error_flag == True:
            return render_template('upload.html' , message = message)
        else:
            return render_template('upload.html' , message = "File succesfully uploaded")

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    if 'username' not in session:
        return redirect(url_for('auth.login'))

    username = session['username']
    file_hash = request.form['file_hash']
    file_key = request.form['file_key']

    request_status = DownloadRequest.query.filter_by(username=username, file_hash=file_hash).first()

    if request_status is None:
        new_request = DownloadRequest(username=username, file_hash=file_hash, status="Pending", timestamp=datetime.utcnow())
        db.session.add(new_request)
        db.session.commit()
        flash("✅ Your download request has been sent to the admin for approval.", "info")
        return redirect(url_for('download'))

    elif request_status.status == "Pending":
        flash("⏳ Your request is still pending approval. Please wait.", "warning")
        return redirect(url_for('download'))

    elif request_status.status == "Rejected":
        flash("❌ Your request was rejected. You can try again.", "danger")
        return redirect(url_for('download'))

    file_path = retrieve_from_hash(file_hash, file_key)
    flash("✅ File downloaded successfully!", "success")
    return redirect(url_for('download'))


@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    print(request)

@socketio.on('add_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.add(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('remove_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.remove(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    print(request)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000, debug=False)

