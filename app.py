
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask import Flask, request, jsonify, send_from_directory, send_file
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from instance.config import JWT_SECRET
from flask_migrate import Migrate
from argon2 import PasswordHasher
from dotenv import load_dotenv
import mimetypes
from PIL import Image
import subprocess as sp
import random
import base64
import ffmpeg
import os
import io

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fhost.db'
app.config['JWT_SECRET_KEY'] = JWT_SECRET
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['UPLOAD_FOLDER'] = 'uploads'
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
        return img.resize((new_width, new_height), Image.LANCZOS)


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


@app.route('/api/upload/<path>', methods=['POST'])
@jwt_required()
def upload_file(path):
    token = get_jwt()
    if token['path'] != path:
        return jsonify({'message': 'Unauthorized access'}), 403

    incoming_file = request.files.get('file')
    if incoming_file:
        sanitized_filename = secure_filename(incoming_file.filename)
        upload_path = str(os.path.join(app.config['UPLOAD_FOLDER'], token['path'], 'src', sanitized_filename))
        thumbnail_path = str(os.path.join(app.config['UPLOAD_FOLDER'], token['path'], 'thumbnails', f'thumbnail_{sanitized_filename.split(".")[0]}.jpg'))
        incoming_file.save(upload_path)
        try:
            result = sp.run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', upload_path], stdout=sp.PIPE, stderr=sp.PIPE)
            video_duration = float(result.stdout)
            random_time = random.uniform(0, video_duration)
            ffmpeg.input(upload_path, ss=random_time).output(thumbnail_path, vframes=1).run(overwrite_output=True)
        except (Exception,) as e:
            print(f"Failed extracting thumbnail: {e}")
            return jsonify({'message': 'Error creating thumbnail from video'}), 500

        return jsonify({'message': 'File uploaded successfully'}), 200

    return jsonify({'message': 'No file provided'}), 400


@app.route('/<path>/thumbnails', methods=['GET'])
@jwt_required()
def thumbnails(path):
    token = get_jwt()
    if token['path'] != path:
        return jsonify({'message': 'Unauthorized access'}), 403

    try:
        media_thumbnails = []
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
        video_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.webm']

        for filename in os.listdir(f'uploads/{path}/src'):
            file_path = os.path.join('uploads', path, 'src', filename)
            if os.path.isfile(file_path):
                _, ext = os.path.splitext(filename)
                ext = ext.lower()

                try:
                    if ext in image_extensions:
                        img = create_thumbnail(file_path)
                        if img.mode != 'RGB':
                            img = img.convert('RGB')

                        buffer = io.BytesIO()
                        img.save(buffer, format='JPEG')
                        thumbnail_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

                    elif ext in video_extensions:
                        import subprocess

                        thumbnail_dir = os.path.join('uploads', path, 'thumbnails')
                        os.makedirs(thumbnail_dir, exist_ok=True)

                        thumbnail_path = os.path.join(thumbnail_dir, f"{filename}_thumb.jpg")
                        if not os.path.exists(thumbnail_path):
                            subprocess.run([
                                'ffmpeg',
                                '-i', file_path,
                                '-vframes', '1',
                                '-q:v', '2',
                                thumbnail_path
                            ], check=True)

                        img = create_thumbnail(thumbnail_path)
                        buffer = io.BytesIO()
                        img.save(buffer, format='JPEG')
                        thumbnail_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                    else:
                        continue

                    media_thumbnails.append({
                        'filename': filename,
                        'blobThmb': f'data:image/jpeg;base64,{thumbnail_b64}',
                        'url': f'/{path}/media/{filename}'
                    })

                except Exception as e:
                    print(f"Error processing {filename}: {e}")

        return jsonify(media_thumbnails), 200

    except Exception as e:
        print(f'Something went wrong: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/<path:user_dir>/file/<filename>', methods=['GET'])
@jwt_required()
def serve_file(user_dir, filename):
    try:
        base_media_dir = get_jwt_identity()['media_base_path']
        full_path = os.path.join(base_media_dir, user_dir, filename)

        if not os.path.normpath(full_path).startswith(base_media_dir):
            return jsonify({'error': 'Unauthorized access'}), 403

        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404

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
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


if __name__ == '__main__':
    app.run(port=9999)
