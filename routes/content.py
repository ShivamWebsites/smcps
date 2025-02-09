from flask import Blueprint, request, jsonify
from bson import ObjectId
from extensions import mongo
from models.content import Content
from auth_middleware import token_required, admin_required

bp = Blueprint('content', __name__, url_prefix='/api/content')

@bp.route('/', methods=['GET'])
@token_required
def get_content(current_user):
    # Users can only see their content, admins can see all
    if current_user['role'] == 'admin':
        content = list(mongo.db.content.find())
    else:
        content = list(mongo.db.content.find({'user_id': str(current_user['_id'])}))
    
    for item in content:
        item['_id'] = str(item['_id'])
    return jsonify(content), 200

@bp.route('/', methods=['POST'])
@token_required
def create_content(current_user):
    data = request.get_json()
    content = Content(
        title=data['title'],
        content_type=data['content_type'],
        script=data['script'],
        user_id=str(current_user['_id'])
    )
    
    result = mongo.db.content.insert_one(content.to_dict())
    return jsonify({'message': 'Content created', 'id': str(result.inserted_id)}), 201

@bp.route('/<content_id>', methods=['PUT'])
@token_required
def update_content(current_user, content_id):
    data = request.get_json()
    try:
        # Check ownership or admin status
        content = mongo.db.content.find_one({'_id': ObjectId(content_id)})
        if not content:
            return jsonify({'message': 'Content not found'}), 404
        
        if str(content['user_id']) != str(current_user['_id']) and current_user['role'] != 'admin':
            return jsonify({'message': 'Unauthorized'}), 403
        
        mongo.db.content.update_one(
            {'_id': ObjectId(content_id)},
            {'$set': data}
        )
        return jsonify({'message': 'Content updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Error updating content', 'error': str(e)}), 400