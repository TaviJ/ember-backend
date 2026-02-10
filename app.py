from flask import Flask, jsonify, request, g
from dotenv import load_dotenv
import os
import jwt
import psycopg2, psycopg2.extras
import bcrypt
from auth_middleware import token_required

load_dotenv()

app = Flask(__name__)

def get_db_connection():
    connection = psycopg2.connect(
        host='localhost',
        database='flask_auth_db',
        user=os.getenv('POSTGRES_USERNAME'),
        password=os.getenv('POSTGRES_PASSWORD')
    )
    return connection
    
@app.route('/auth/sign-up', methods=['POST'])
def sign_up():
    try:
        new_user_data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s;", (new_user_data["username"],))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            return jsonify({"err": "Username already taken"}), 400
        hashed_password = bcrypt.hashpw(bytes(new_user_data["password"], 'utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id, username", (new_user_data["username"], hashed_password.decode('utf-8')))
        created_user = cursor.fetchone()
        connection.commit()
        connection.close()
        payload = {"username": created_user["username"], "id": created_user["id"]}
        token = jwt.encode({ "payload": payload }, os.getenv('JWT_SECRET'))
        return jsonify({"token": token}), 201
    except Exception as err:
        return jsonify({"err": str(err)}), 401

@app.route('/auth/sign-in', methods=["POST"])
def sign_in():
    try:
        sign_in_form_data = request.get_json()
        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s;", (sign_in_form_data["username"],))
        existing_user = cursor.fetchone()
        if existing_user is None:
            return jsonify({"err": "Invalid credentials."}), 401
        password_is_valid = bcrypt.checkpw(bytes(sign_in_form_data["password"], 'utf-8'), bytes(existing_user["password"], 'utf-8'))
        if not password_is_valid:
            return jsonify({"err": "Invalid credentials."}), 401
        payload = {"username": existing_user["username"], "id": existing_user["id"]}
        token = jwt.encode({ "payload": payload }, os.getenv('JWT_SECRET'))
        return jsonify({"token": token}), 201
    except Exception as err:
        return jsonify({"err": err.message}), 500
    finally:
        connection.close()

@app.route('/users')
@token_required
def users_index():
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT id, username FROM users;")
    users = cursor.fetchall()
    connection.close()
    return jsonify(users), 200

@app.route('/users/<user_id>')
@token_required
def users_index(user_id):
    # If the user is looking for the details of another user, block the request
    # Send a 403 status code to indicate that the user is unauthorized
    if user_id != g.user["id"]:
        return jsonify({"err": "Unauthorized"}), 403
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT id, username FROM users WHERE id = %s;", (user_id))
    user = cursor.fetchone()
    connection.close()
    if user is None:
        return jsonify({"err": "User not found"}), 404
    return jsonify(user), 200

# Run our application, by default on port 5000
app.run()