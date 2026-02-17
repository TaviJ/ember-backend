from flask import Flask, jsonify, request, g
from dotenv import load_dotenv
import os
import jwt
import psycopg2, psycopg2.extras
import bcrypt
from auth_middleware import token_required
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app)


# ---------------------------
# Database Connection
# ---------------------------
def get_db_connection():
    if 'ON_HEROKU' in os.environ:
        connection = psycopg2.connect(
            os.getenv('DATABASE_URL'), 
            sslmode='require'
        )
    else:
        connection = psycopg2.connect(
            host='localhost',
            database=os.getenv('POSTGRES_DATABASE'),
            user=os.getenv('POSTGRES_USERNAME'),
            password=os.getenv('POSTGRES_PASSWORD')
        )
    return connection



def to_bool(value):
    return value is True or value == True or value == "true" or value == "True" or value == 1


# ---------------------------
# AUTH ROUTES
# ---------------------------
@app.route('/auth/sign-up', methods=['POST'])
def sign_up():
    try:
        data = request.get_json()

        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cursor.execute("SELECT * FROM users WHERE username = %s;", (data["username"],))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"err": "Username already taken"}), 400

        hashed_password = bcrypt.hashpw(
            data["password"].encode('utf-8'),
            bcrypt.gensalt()
        )

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id, username;",
            (data["username"], hashed_password.decode('utf-8'))
        )

        created_user = cursor.fetchone()
        connection.commit()
        connection.close()

        payload = {
            "id": created_user["id"],
            "username": created_user["username"]
        }

        token = jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm="HS256")

        return jsonify({"token": token}), 201

    except Exception as err:
        return jsonify({"err": str(err)}), 500



@app.route('/auth/sign-in', methods=["POST"])
def sign_in():
    try:
        data = request.get_json()

        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cursor.execute("SELECT * FROM users WHERE username = %s;", (data["username"],))
        existing_user = cursor.fetchone()

        if existing_user is None:
            return jsonify({"err": "Invalid credentials"}), 401

        password_is_valid = bcrypt.checkpw(
            data["password"].encode("utf-8"),
            existing_user["password"].encode("utf-8")
        )

        if not password_is_valid:
            return jsonify({"err": "Invalid credentials"}), 401

        payload = {
            "id": existing_user["id"],
            "username": existing_user["username"]
        }

        token = jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm="HS256")

        connection.close()
        return jsonify({"token": token}), 200

    except Exception as err:
        return jsonify({"err": str(err)}), 500


# ---------------------------
# USER ROUTES
# ---------------------------
@app.route('/users', methods=['GET'])
@token_required
def users_index():
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT id, username FROM users;")
    users = cursor.fetchall()

    connection.close()
    return jsonify(users), 200


@app.route('/users/<user_id>', methods=['GET'])
@token_required
def users_show(user_id):

    if int(user_id) != int(g.user["id"]):
        return jsonify({"err": "Unauthorized"}), 403

    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT id, username FROM users WHERE id = %s;", (user_id,))
    user = cursor.fetchone()

    connection.close()

    if user is None:
        return jsonify({"err": "User not found"}), 404

    return jsonify(user), 200


# ---------------------------
# LOG ENTRY ROUTES
# ---------------------------

# GET my entries
@app.route('/log-entries', methods=['GET'])
@token_required
def log_entries_index():
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("""
        SELECT id, user_id, entry_date, mood, activity, note, is_public, created_at, updated_at
        FROM log_entries
        WHERE user_id = %s
        ORDER BY entry_date DESC, created_at DESC;
    """, (g.user["id"],))

    entries = cursor.fetchall()
    connection.close()
    return jsonify(entries), 200


# GET single entry
@app.route('/log-entries/<entry_id>', methods=['GET'])
@token_required
def log_entries_show(entry_id):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("""
        SELECT id, user_id, entry_date, mood, activity, note, is_public, created_at, updated_at
        FROM log_entries
        WHERE id = %s AND user_id = %s;
    """, (entry_id, g.user["id"]))

    entry = cursor.fetchone()
    connection.close()

    if entry is None:
        return jsonify({"err": "Log entry not found"}), 404

    return jsonify(entry), 200


# CREATE entry
@app.route('/log-entries', methods=['POST'])
@token_required
def log_entries_create():
    try:
        data = request.get_json()

        entry_date = data.get("entry_date")
        mood = data.get("mood")
        activity = data.get("activity")
        note = data.get("note")
        is_public = to_bool(data.get("is_public", False))

        if not mood or not activity:
            return jsonify({"err": "Mood and activity are required"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cursor.execute("""
            INSERT INTO log_entries (user_id, entry_date, mood, activity, note, is_public)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, user_id, entry_date, mood, activity, note, is_public, created_at, updated_at;
        """, (g.user["id"], entry_date, mood, activity, note, is_public))

        created = cursor.fetchone()
        connection.commit()
        connection.close()

        return jsonify(created), 201

    except Exception as err:
        return jsonify({"err": str(err)}), 500


# UPDATE entry
@app.route('/log-entries/<entry_id>', methods=['PUT'])
@token_required
def log_entries_update(entry_id):
    try:
        data = request.get_json()

        entry_date = data.get("entry_date")
        mood = data.get("mood")
        activity = data.get("activity")
        note = data.get("note")
        is_public = to_bool(data.get("is_public", False))

        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cursor.execute("""
            UPDATE log_entries
            SET entry_date = %s,
                mood = %s,
                activity = %s,
                note = %s,
                is_public = %s,
                updated_at = now()
            WHERE id = %s AND user_id = %s
            RETURNING id, user_id, entry_date, mood, activity, note, is_public, created_at, updated_at;
        """, (entry_date, mood, activity, note, is_public, entry_id, g.user["id"]))

        updated = cursor.fetchone()
        connection.commit()
        connection.close()

        if updated is None:
            return jsonify({"err": "Not found or unauthorized"}), 404

        return jsonify(updated), 200

    except Exception as err:
        return jsonify({"err": str(err)}), 500


# DELETE entry
@app.route('/log-entries/<entry_id>', methods=['DELETE'])
@token_required
def log_entries_delete(entry_id):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("""
        DELETE FROM log_entries
        WHERE id = %s AND user_id = %s
        RETURNING id;
    """, (entry_id, g.user["id"]))

    deleted = cursor.fetchone()
    connection.commit()
    connection.close()

    if deleted is None:
        return jsonify({"err": "Not found or unauthorized"}), 404

    return jsonify({"message": "Deleted"}), 200


# PUBLIC FEED
@app.route('/public/log-entries', methods=['GET'])
def public_log_entries_index():
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("""
        SELECT
            le.id,
            le.entry_date,
            le.mood,
            le.activity,
            le.note,
            le.created_at,
            le.updated_at,
            u.username
        FROM log_entries le
        JOIN users u ON u.id = le.user_id
        WHERE le.is_public = true
        ORDER BY le.entry_date DESC, le.created_at DESC;
    """)

    entries = cursor.fetchall()
    connection.close()

    
    for e in entries:
        if e.get("entry_date"):
            e["entry_date"] = e["entry_date"].isoformat()
        if e.get("created_at"):
            e["created_at"] = e["created_at"].isoformat()
        if e.get("updated_at"):
            e["updated_at"] = e["updated_at"].isoformat()

    return jsonify(entries), 200


# ---------------------------
# RUN SERVER
# ---------------------------
if __name__ == "__main__":
    app.run()
