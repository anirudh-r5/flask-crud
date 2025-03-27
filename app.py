import os
import bcrypt
import psycopg
from functools import wraps

from flask import Flask, request, jsonify, abort, g, session
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from src.errors import error_handlers
from src.auth import generate_jwt_token, token_required

# Loads environment variables from .env
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

app = Flask(__name__)
# Sets the Flask application's secret key for sessions/JWT
app.config["SECRET_KEY"] = SECRET_KEY

# Configures file upload folder and creates it if missing
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Restricts maximum upload size to 2MB
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

def get_db_connection():
    """Establishes a connection to the Postgres database."""
    return psycopg.connect(DATABASE_URL)

# Registers global error handlers for the Flask app
error_handlers(app)

@app.route("/", methods=["GET"])
def home():
    """Fetches rows from the 'open' table and returns them as JSON."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM open;")
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()

    results = []
    for row in rows:
        row_dict = dict(zip(columns, row))
        results.append(row_dict)

    return jsonify(results), 200

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

def allowed_file(filename):
    """Checks if a file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/register", methods=["POST"])
def register():
    """Registers a new user with a hashed password."""
    data = request.json or {}
    username = data.get("username")
    raw_password = data.get("password")

    if not username or not raw_password:
        abort(400, description="Username and password are required")

    # Hashes the password with bcrypt
    hashed_password = bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt())

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Checks if the user already exists
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    abort(400, description="User already exists")

                # Inserts the new user into the 'users' table
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
    """Authenticates a user and returns a JWT token."""
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        abort(400, description="Username and password are required")

    # Fetches the user record and verifies the password
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                abort(401, description="User not found")

            user_id, stored_hashed = row
            if not bcrypt.hashpw(password.encode("utf-8"), stored_hashed.encode("utf-8")) == stored_hashed.encode("utf-8"):
                abort(401, description="Invalid credentials")

    # Generates a JWT token upon successful authentication
    token = generate_jwt_token(user_id, app.config["SECRET_KEY"])
    return jsonify({"token": token}), 200

@app.route("/upload", methods=["POST"])
@token_required(app.config["SECRET_KEY"])
def upload_file():
    """Handles file uploads for authenticated users."""
    if "file" not in request.files:
        abort(400, description="No file found in request key ")

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

@app.route("/items", methods=["POST"])
@token_required(app.config["SECRET_KEY"])
def create_item():
    """Creates a new item in the 'items' table."""
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
@token_required(app.config["SECRET_KEY"])
def get_items():
    """Fetches all items from the 'items' table."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description FROM items")
            rows = cur.fetchall()
    items = [
        {"id": row[0], "name": row[1], "description": row[2]} for row in rows
    ]
    return jsonify(items), 200

@app.route("/items/<int:item_id>", methods=["GET"])
@token_required(app.config["SECRET_KEY"])
def get_item(item_id):
    """Fetches a single item by ID."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description FROM items WHERE id = %s", (item_id,))
            row = cur.fetchone()
            if not row:
                abort(404, description="Item not found")
    item = {"id": row[0], "name": row[1], "description": row[2]}
    return jsonify(item), 200

@app.route("/items/<int:item_id>", methods=["PUT"])
@token_required(app.config["SECRET_KEY"])
def update_item(item_id):
    """Updates an existing item in the 'items' table."""
    data = request.json or {}
    name = data.get("name")
    description = data.get("description")

    if not name:
        abort(400, description="Name is required for update")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Checks if the item exists
            cur.execute("SELECT id FROM items WHERE id = %s", (item_id,))
            if not cur.fetchone():
                abort(404, description="Item not found")

            # Updates the item
            cur.execute(
                "UPDATE items SET name = %s, description = %s WHERE id = %s",
                (name, description, item_id)
            )
        conn.commit()

    return jsonify({"id": item_id, "name": name, "description": description}), 200

@app.route("/items/<int:item_id>", methods=["DELETE"])
@token_required(app.config["SECRET_KEY"])
def delete_item(item_id):
    """Deletes an item from the 'items' table."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Checks if the item exists
            cur.execute("SELECT id FROM items WHERE id = %s", (item_id,))
            if not cur.fetchone():
                abort(404, description="Item not found")

            # Removes the item if it exists
            cur.execute("DELETE FROM items WHERE id = %s", (item_id,))
        conn.commit()

    return jsonify({"message": f"Item {item_id} deleted"}), 200

if __name__ == "__main__":
    # Runs the Flask app in debug mode for development
    app.run(debug=True)
