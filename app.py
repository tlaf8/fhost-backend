from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from instance.config import JWT_SECRET
from flask_migrate import Migrate
from argon2 import PasswordHasher
from dotenv import load_dotenv
from datetime import timedelta
from PIL import Image
import subprocess as sp
import mimetypes
import random
import base64
import ffmpeg
import os
import io

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fhost.db'
app.config['JWT_SECRET_KEY'] = JWT_SECRET
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['USE_CORS'] = True
load_dotenv()
db = SQLAlchemy(app)
from models import User

migrate = Migrate(app, db)
jwt = JWTManager(app)
ph = PasswordHasher()


def create_thumbnail(image_path, max_width=300, max_height=300):
    with Image.open(image_path) as img:
        original_width, original_height = img.size
        ratio = min(
            max_width / original_width,
            max_height / original_height
        )
        new_width = int(original_width * ratio)
        new_height = int(original_height * ratio)
        return img.resize((new_width, new_height), Image.Resampling.LANCZOS)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    dirname = os.urandom(16).hex()
    hashed_password = ph.hash(password)

    user = User(username=username, email=email, password=hashed_password, dirname=dirname)
    db.session.add(user)
    db.session.commit()

    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(os.path.join(user_dir, 'src'), exist_ok=True)
    os.makedirs(os.path.join(user_dir, 'thumbnails'), exist_ok=True)

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user:
        try:
            ph.verify(user.password, password)
            additional_claims = {
                'id': user.id,
                'username': username,
                'path': user.dirname,
            }
            token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
            return jsonify({'token': token}), 200
        except (Exception,) as e:
            print(f'Failed login: {e}')
            return jsonify({'message': 'Invalid credentials'}), 401

    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/api/token', methods=['GET'])
@jwt_required()
def decode():
    token = get_jwt()
    return jsonify({
        'id': token['id'],
        'username': token['username'],
        'path': token['path']
    }), 200


@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    path = request.headers.get('path')
    if not path:
        return jsonify({'message': 'Path header missing'}), 400

    token = get_jwt()
    if token['path'] != path:
        return jsonify({'message': 'Unauthorized access'}), 403

    incoming_file = request.files.get('file')
    if incoming_file:
        filename = request.headers.get('filename')
        if filename == '':
            filename = incoming_file.filename
            
        sanitized_filename = secure_filename(filename)
        upload_path = str(os.path.join(app.config['UPLOAD_FOLDER'], token['path'], 'src', sanitized_filename))
        thumbnail_path = str(os.path.join(app.config['UPLOAD_FOLDER'], token['path'], 'thumbnails',
                                          f'thumbnail_{sanitized_filename.split(".")[0]}.png'))
        if os.path.exists(upload_path) or os.path.exists(thumbnail_path):
            return jsonify({'message': 'File already exists'}), 409

        incoming_file.save(upload_path)
        if os.path.splitext(sanitized_filename)[1] in ['.gif', '.mp4', '.mov', '.avi']:
            try:
                result = sp.run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of',
                                 'default=noprint_wrappers=1:nokey=1', upload_path], stdout=sp.PIPE, stderr=sp.PIPE)
                random_time = random.uniform(0, float(result.stdout))
                ffmpeg.input(upload_path, ss=random_time).output(thumbnail_path, vframes=1).run(overwrite_output=False)
                create_thumbnail(thumbnail_path).save(thumbnail_path)
            except (Exception,) as e:
                print(f"Failed extracting thumbnail: {e}")
                return jsonify({'message': f'Error creating thumbnail from video: {e}'}), 500
        else:
            create_thumbnail(upload_path).save(thumbnail_path)

        return jsonify({'message': 'File uploaded successfully'}), 200

    return jsonify({'message': 'No file provided'}), 400


@app.route('/api/thumbnails', methods=['GET'])
@jwt_required()
def thumbnails():
    path = request.headers.get('path')
    if not path:
        return jsonify({'message': 'Path header missing'}), 400

    filename = request.headers.get('filename')
    if not filename:
        return jsonify({'message': 'Filename header missing'}), 400

    if filename == 'gimmefiles':
        return jsonify({'files': os.listdir(os.path.join(app.config['UPLOAD_FOLDER'], path, 'src'))}), 200

    token = get_jwt()
    if token['path'] != path:
        return jsonify({'message': 'Unauthorized access'}), 403

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], path, 'thumbnails', f'thumbnail_{os.path.splitext(filename)[0]}.png')
    if os.path.isfile(file_path):
        img = Image.open(file_path)
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        thumbnail_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return jsonify({
            'filename': filename,
            'blobThmb': f'data:image/jpeg;base64,{thumbnail_b64}',
            'url': f'/{path}/media/{filename}'
        })

    else:
        return jsonify({'message': f'Cannot find file: {file_path}'}), 404


@app.route('/api/media', methods=['GET'])
@jwt_required()
def serve_file():
    path = request.headers.get('path')
    if not path:
        return jsonify({'message': 'Path header missing'}), 400

    filename = request.headers.get('filename')
    if not filename:
        return jsonify({'message': 'Filename header missing'}), 400

    try:
        token = get_jwt()
        if token['path'] != path:
            return jsonify({'message': 'Unauthorized access'}), 403

        full_path = os.path.join(app.config['UPLOAD_FOLDER'], path, 'src', filename)
        if not os.path.exists(full_path):
            return jsonify({'error': f'File not found in {path}'}), 404

        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'

        return send_file(
            str(full_path),
            mimetype=mime_type,
            as_attachment=False
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.after_request
def add_cors_headers(response):
    if app.config.get('USE_CORS'):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, filename, path'
    return response


if __name__ == '__main__':
    app.run(port=9999)
