from flask import Flask
from config.config import Config
from extensions import mongo
from flask_cors import CORS
from routes import auth, trend, content, media, analytics, admin, profile

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize MongoDB
    mongo.init_app(app)
    # Enable CORS dynamically for all routes
    CORS(app, resources={r"/*": {"origins": "*"}}) 
    
    # Register blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(trend.bp)
    app.register_blueprint(content.bp)
    app.register_blueprint(media.bp)
    app.register_blueprint(analytics.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(profile.bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)