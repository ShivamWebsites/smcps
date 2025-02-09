from flask import Blueprint

bp = Blueprint('analytics', __name__)

@bp.route('/analytics/example')
def example():
    return "Analytics route example!"
