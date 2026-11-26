from flask import Flask, request
from job_tracker.jobs.routes import jobs_bp
from job_tracker.auth.routes import auth_bp
from flask_jwt_extended import JWTManager
import logging
import logging.config
from job_tracker.logging_config import LOGGING_CONFIG
import time
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
logging.config.dictConfig(LOGGING_CONFIG)
load_dotenv()

def create_app():

    app = Flask(__name__)

    # Set the JWT secret key from environment variable 
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    if not JWT_SECRET_KEY:
        logger.error("JWT_SECRET_KEY environment variable is not set")
        raise ValueError("JWT_SECRET_KEY environment variable is not set")

    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    JWTManager(app)

    app.register_blueprint(jobs_bp)
    app.register_blueprint(auth_bp)
    logger.info("Flask configuration completed")

    # Set up logging for the Flask app using before_request and after_request hooks
    @app.before_request
    def start_timer():
        request.start_time = time.time()

        app.logger.info(f"Incoming request: {request.method} {request.path} "
                        f"| IP: {request.remote_addr}"
                        )
        
    @app.after_request
    def log_request(response):
        duration = time.time() - request.start_time
        app.logger.info(f"Request completed: {request.method} {request.path} "
                        f"| Status: {response.status_code} | Duration: {duration:.4f}s"
                        )
        return response    
    
    return app
    
if __name__ == '__main__':
    app = create_app()

    logger.info("Flask application started")
    app.run(debug=False)