from flask import Blueprint, request, jsonify
from bson import ObjectId
from extensions import mongo
from auth_middleware import admin_required

bp = Blueprint('admin', __name__, url_prefix='/api/admin')

@bp.route('/users', methods=['GET'])
@admin_required
def get_users(current_user):
    users = list(mongo.db.users.find({}, {'password': 0}))
    for user in users:
        user['_id'] = str(user['_id'])
    return jsonify(users), 200

@bp.route('/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(current_user, user_id):
    data = request.get_json()
    try:
        mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {k: v for k, v in data.items() if k != 'password' and k != 'role'}}
        )
        return jsonify({'message': 'User updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Error updating user', 'error': str(e)}), 400

@bp.route('/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    try:
        result = mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count:
            return jsonify({'message': 'User deleted successfully'}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error deleting user', 'error': str(e)}), 400
    
@bp.route('/users/<user_id>/block', methods=['PUT'])
@admin_required
def block_user(current_user, user_id):
    try:
        result = mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'status': 'blocked'}}
        )
        if result.matched_count:
            return jsonify({'message': 'User blocked successfully'}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error blocking user', 'error': str(e)}), 400
    

@bp.route('/analytics', methods=['GET'])
@admin_required
def get_analytics(current_user):
    # Get system-wide analytics
    user_count = mongo.db.users.count_documents({'role': 'user'})
    content_count = mongo.db.content.count_documents({})
    trend_count = mongo.db.trends.count_documents({})
    
    return jsonify({
        'user_count': user_count,
        'content_count': content_count,
        'trend_count': trend_count
    }), 200