from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from job_tracker.extensions import users_collection
import bcrypt
import logging
import re
from ratelimit import limits, sleep_and_retry

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

# Declare the route and add a limit of 5 requests per minute
@auth_bp.route('/register', methods=['POST'])
@sleep_and_retry
@limits(calls=5, period=60)
def register():
    data = request.get_json()

    # Validate the existence of JSON data and required fields
    if not isinstance(data, dict):
        logger.warning("Registration attempt with invalid input")
        return jsonify({"error": "Invalid input"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        logger.warning("Registration attempt with missing fields")
        return jsonify({"error": "Missing fields"}), 400

    # Validate data types
    if not isinstance(username, str) or not isinstance(password, str):
        logger.warning("Registration attempt with invalid data types")
        return jsonify({"error": "Invalid data types"}), 400
    
    # Validate password
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,72}$", password):
        logger.warning("Registration attempt with invalid password")
        return jsonify({"error": "Invalid password"}), 400

    existing_user = users_collection.find_one({"username": username})

    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    user = {
        "username": username,
        "password": hashed_password
    }

    users_collection.insert_one(user)

    logger.info(f"User registered: {username}")
    return jsonify({"message": "User registered"}), 201

@auth_bp.route('/login', methods=['POST'])
@sleep_and_retry
@limits(calls=5, period=60)
def login():
    data = request.get_json()

    # Validate the existence of JSON data
    if not isinstance(data, dict):
        logger.warning("Login attempt with invalid input")
        return jsonify({"error": "Invalid input"}), 400

    username = data.get("username")
    password = data.get("password")

    # Validate data types
    if not isinstance(username, str) or not isinstance(password, str):
        logger.warning("Login attempt with invalid data types")
        return jsonify({"error": "Invalid data types"}), 400

    if not username or not password:
        logger.warning("Login attempt with missing fields")
        return jsonify({"error": "Missing fields"}), 400

    if len(password.encode("utf-8")) > 72:
        logger.warning(f"Login attempt with oversized password for username: {username}")
        return jsonify({"error": "Invalid password length"}), 400

    user = users_collection.find_one({"username": username})

    # Validate user existence and password
    if not user:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Validate the password is correct
    if not bcrypt.checkpw(
        password.encode('utf-8'),
        user["password"]
    ):
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)

    logger.info(f"User logged in: {username}")
    return jsonify(access_token=access_token), 200