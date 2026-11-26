import os

# Create a Config class to hold configuration variables, namely the MongoDB URI and database name, as well as the JWT secret key.
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

    MONGO_URI = os.environ.get("MONGO_URI")
    MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "job_tracker")

    # Rate limiting defaults
    RATELIMIT_DEFAULT = "100 per hour"