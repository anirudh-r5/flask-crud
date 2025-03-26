import os
import jwt  # PyJWT
import bcrypt
import psycopg
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, abort, g
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

def get_db_connection():
    return psycopg.connect(DATABASE_URL)

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "message": str(error)}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "message": str(error)}), 500

def generate_jwt_token(user_id):
    expiration_time = datetime.now() + timedelta(hours=1)
    payload = {
        "user_id": user_id,
        "exp": expiration_time
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            abort(401, description="Missing Authorization header")

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            abort(401, description="Invalid Authorization header format")

        token = parts[1]
        try:
            decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user_id = decoded.get("user_id")
            if not user_id:
                abort(401, description="Invalid token payload")

            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
                    row = cur.fetchone()
                    if not row:
                        abort(401, description="User no longer exists")
                    g.current_user = {"id": row[0], "username": row[1]}

        except jwt.ExpiredSignatureError:
            abort(401, description="Token has expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")

        return f(*args, **kwargs)
    return decorated

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
@token_required
def upload_file():
    if "file" not in request.files:
        abort(400, description="No file found in request")

    file = request.files["file"]
    if file.filename == "":
        abort(400, description="No file selected")

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        return jsonify({"message": "File uploaded successfully"}), 201
    else:
        abort(400, description="File type not allowed")


@app.route("/items", methods=["GET"])
def public_items():
    data = [
        {"id": 1, "name": "PublicItemA"},
        {"id": 2, "name": "PublicItemB"}
    ]
    return jsonify(data), 200

@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username")
    raw_password = data.get("password")

    if not username or not raw_password:
        abort(400, description="Username and password are required")

    hashed_password = bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt())

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    abort(400, description="User already exists")

                cur.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id",
                    (username, hashed_password.decode("utf-8"))
                )
                new_id = cur.fetchone()[0]
            conn.commit()
    except Exception as e:
        abort(500, description=str(e))

    return jsonify({"message": "User registered successfully", "user_id": new_id}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        abort(400, description="Username and password are required")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                abort(401, description="Invalid credentials")

            user_id, stored_hashed = row
            if not bcrypt.hashpw(password.encode("utf-8"), stored_hashed.encode("utf-8")) == stored_hashed.encode("utf-8"):
                abort(401, description="Invalid credentials")

    token = generate_jwt_token(user_id)
    return jsonify({"token": token}), 200


@app.route("/items", methods=["POST"])
@token_required
def create_item():
    data = request.json or {}
    name = data.get("name")
    description = data.get("description", "")

    if not name:
        abort(400, description="Item name is required")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO items (name, description) VALUES (%s, %s) RETURNING id",
                (name, description)
            )
            item_id = cur.fetchone()[0]
        conn.commit()

    return jsonify({"id": item_id, "name": name, "description": description}), 201

@app.route("/items", methods=["GET"])
@token_required
def get_items():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description FROM items")
            rows = cur.fetchall()
    items = [
        {"id": row[0], "name": row[1], "description": row[2]} for row in rows
    ]
    return jsonify(items), 200

@app.route("/items/<int:item_id>", methods=["GET"])
@token_required
def get_item(item_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description FROM items WHERE id = %s", (item_id,))
            row = cur.fetchone()
            if not row:
                abort(404, description="Item not found")
    item = {"id": row[0], "name": row[1], "description": row[2]}
    return jsonify(item), 200

@app.route("/items/<int:item_id>", methods=["PUT"])
@token_required
def update_item(item_id):
    data = request.json or {}
    name = data.get("name")
    description = data.get("description")

    if not name:
        abort(400, description="Name is required for update")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM items WHERE id = %s", (item_id,))
            if not cur.fetchone():
                abort(404, description="Item not found")

            cur.execute(
                "UPDATE items SET name = %s, description = %s WHERE id = %s",
                (name, description, item_id)
            )
        conn.commit()

    return jsonify({"id": item_id, "name": name, "description": description}), 200

@app.route("/items/<int:item_id>", methods=["DELETE"])
@token_required
def delete_item(item_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM items WHERE id = %s", (item_id,))
            if not cur.fetchone():
                abort(404, description="Item not found")

            cur.execute("DELETE FROM items WHERE id = %s", (item_id,))
        conn.commit()

    return jsonify({"message": f"Item {item_id} deleted"}), 200

if __name__ == "__main__":
    app.run(debug=True)
