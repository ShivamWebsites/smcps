from flask import Blueprint

bp = Blueprint('media', __name__)

@bp.route('/example')
def example():
    return "Media route example!"
