from flask import Blueprint, request, jsonify
from extensions import mongo
from models.user import User
from bson.objectid import ObjectId 
import os
from werkzeug.utils import secure_filename

bp = Blueprint('profile', __name__, url_prefix='/api')

# Configure upload folder
UPLOAD_FOLDER = 'uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route("/profile", methods=["POST"])
def create_profile():
    data = request.form
    profile_picture = request.files.get("profile_picture")

    # Validate required fields
    if not all(key in data for key in ("email", "password", "confirm_password", "full_name")):
        return jsonify({"error": "Missing required fields"}), 400

    if data["password"] != data["confirm_password"]:
        return jsonify({"error": "Passwords do not match"}), 400

    # Save profile picture if provided
    picture_path = None
    if profile_picture and allowed_file(profile_picture.filename):
        filename = secure_filename(profile_picture.filename)
        picture_path = os.path.join(UPLOAD_FOLDER, filename)
        profile_picture.save(picture_path)

    # Create a new user
    user = User(
        email=data["email"],
        password=data["password"],
        full_name=data["full_name"],
        business_name=data.get("business_name"),
        profile_picture=picture_path
    )

    # Insert into the database
    user_id = mongo.db.users.insert_one(user.to_dict()).inserted_id
    return jsonify({"message": "User created successfully", "user_id": str(user_id)}), 201

@bp.route("/profile/<user_id>", methods=["GET"])
def get_profile(user_id):
    try:
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        user["_id"] = str(user["_id"])
        return jsonify(user), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@bp.route("/profile/<user_id>", methods=["PUT"])
def update_profile(user_id):
    data = request.form
    profile_picture = request.files.get("profile_picture")
    updates = {}

    try:
        # Save new profile picture if provided
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            picture_path = os.path.join(UPLOAD_FOLDER, filename)
            profile_picture.save(picture_path)
            updates["profile_picture"] = picture_path

        # Update preferences if provided
        if "preferences" in data:
            updates["preferences"] = data.get("preferences")

        # Update other fields if provided
        for field in ["full_name", "business_name"]:
            if field in data:
                updates[field] = data[field]

        if updates:
            mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": updates})
            return jsonify({"message": "Profile updated successfully"}), 200
        else:
            return jsonify({"error": "No updates provided"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@bp.route("/profile/<user_id>", methods=["DELETE"])
def delete_profile(user_id):
    try:
        result = mongo.db.users.delete_one({"_id": ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"message": "Profile deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
