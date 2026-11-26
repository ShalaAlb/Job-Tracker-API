from pymongo import MongoClient
from config import Config
client = MongoClient(Config.MONGO_URI)

db = client[Config.MONGO_DB_NAME]
jobs_collection = db["jobs"]
users_collection = db["users"]