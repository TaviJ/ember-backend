from flask import request, jsonify, g
import jwt
import os
from functools import wraps


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"err": "Authorization header missing"}), 401

        try:
            token = auth_header.split(" ")[1]
            decoded = jwt.decode(
                token,
                os.getenv("JWT_SECRET"),
                algorithms=["HS256"]
            )

            
            g.user = decoded

        except Exception as e:
            return jsonify({"err": "Signature verification failed"}), 401

        return f(*args, **kwargs)

    return decorated
