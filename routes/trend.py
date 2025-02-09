from flask import Blueprint, request, jsonify
from bson import ObjectId
from models.trend import Trend
from extensions import mongo
from auth_middleware import token_required

bp = Blueprint('trend', __name__, url_prefix='/api/trends')

@bp.route('/', methods=['GET'])
@token_required
def get_trends(current_user):
    trends = list(mongo.db.trends.find())
    for trend in trends:
        trend['_id'] = str(trend['_id'])
    return jsonify(trends), 200

@bp.route('/', methods=['POST'])
@token_required
def create_trend(current_user):
    data = request.get_json()
    trend = Trend(
        title=data['title'],
        platform=data['platform'],
        engagement_metrics=data['engagement_metrics'],
        sentiment_score=data.get('sentiment_score')
    )
    
    result = mongo.db.trends.insert_one(trend.to_dict())
    return jsonify({'message': 'Trend created', 'id': str(result.inserted_id)}), 201

@bp.route('/<trend_id>', methods=['GET'])
@token_required
def get_trend(current_user, trend_id):
    try:
        trend = mongo.db.trends.find_one({'_id': ObjectId(trend_id)})
        if not trend:
            return jsonify({'message': 'Trend not found'}), 404
        trend['_id'] = str(trend['_id'])
        return jsonify(trend), 200
    except Exception as e:
        return jsonify({'message': 'Invalid trend ID', 'error': str(e)}), 400
    