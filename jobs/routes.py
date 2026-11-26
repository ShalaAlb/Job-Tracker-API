from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson import ObjectId
from job_tracker.extensions import jobs_collection
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)
jobs_bp = Blueprint('jobs', __name__)

@jobs_bp.route('/jobs', methods=['POST'])
@jwt_required()
def create_job():
    data = request.get_json()
    current_user = get_jwt_identity()

    # Validate the existence of the required fields
    if data is None:
        logger.warning(f"Job creation attempt with invalid input for user: {current_user}")
        return jsonify({"error": "Request must be JSON"}), 400

    if not data.get("title") or not data.get("company"):
        logger.warning(f"Job creation attempt with missing required fields for user: {current_user}")
        return jsonify({"error": "Missing required fields"}), 400

    # TODO: Consider omitting optional fields instead of storing null values.
    # TODO: Add extra entries for filtering and pagination info
    # Extract given fields and set default values for optional fields
    job = {
        "title": data.get("title"),
        "company": data.get("company"),
        "status": "Applied",
        "date_applied": datetime.now(timezone.utc),
        "resume": data.get("resume"),
        "notes": data.get("notes"),
        "location": data.get("location"),
        "application_url": data.get("application_url"),
        "username": current_user
    }

    # Add the job to the Mongo database
    result = jobs_collection.insert_one(job)

    # Convert ObjectId to string for JSON serialization
    job["_id"] = str(result.inserted_id)

    logger.info(f"Job created: {job['title']} for user: {current_user}")
    return jsonify(job), 201

@jobs_bp.route('/jobs', methods=['GET'])
@jwt_required()
def get_jobs():
    current_user = get_jwt_identity()

    # Retrieve the query parameters for filtering, sorting, and pagination
    status = request.args.get("status")
    company = request.args.get("company")
    location = request.args.get("location")
    resume = request.args.get("resume")

    # Sort and order parameters with default values. These can be changed to any of the allowed values. See README for more details.
    sort = request.args.get("sort", "date_applied")

    # TODO: Add a secondary sorting mechanism to act as a tiebreaker of sorts
    order = request.args.get("order", "desc")

    # Check if the provided sort and order values are valid
    if order not in ["asc", "desc"]:
        logger.warning(f"Invalid order value: {order} for user: {current_user}")
        return jsonify({"error": "Invalid order value"}), 400

    if sort not in ["date_applied", "title", "company", "status"]:
        logger.warning(f"Invalid sort value: {sort} for user: {current_user}")
        return jsonify({"error": "Invalid sort value"}), 400

    # Set default values for pagination parameters and validate them. These can also be changed to any positive integer values. See README for more details.
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 10))
    except (ValueError, TypeError):
        logger.warning(f"Invalid page or limit values for user: {current_user}")
        return jsonify({"error": "Invalid page or limit values"}), 400

    if page < 1 or limit < 1:
        logger.warning(f"Page and limit must be positive integers for user: {current_user}")
        return jsonify({"error": "Page and limit must be positive integers"}), 400

    # Calculate the number of documents to skip based on the current page and limit
    skip = (page - 1) * limit

    jobs = []
    
    query = {"username": current_user}
    
    if status:
        query["status"] = status
    
    if company:
        query["company"] = company

    if location:
        query["location"] = location

    if resume:
        query["resume"] = resume

    if order == "desc":
        order_value = -1
    else:
        order_value = 1

    # Retrieve the jobs from the Mongo database based on the query, sort, and pagination parameters
    for job in jobs_collection.find(query).sort(sort, order_value).skip(skip).limit(limit):
        job["_id"] = str(job["_id"])
        jobs.append(job)

    logger.info(f"Jobs retrieved for user: {current_user}")
    return jsonify(jobs), 200

@jobs_bp.route('/jobs/<job_id>', methods=['GET'])
@jwt_required()
def get_job(job_id):
    current_user = get_jwt_identity()

    try:
        job = jobs_collection.find_one({"_id": ObjectId(job_id), "username": current_user})
    except Exception:
        logger.warning(f"Invalid job ID format: {job_id} for user: {current_user}")
        return jsonify({"error": "Invalid ID format"}), 400

    if job is None:
        logger.warning(f"Job {job_id} not found for user: {current_user}")
        return jsonify({"error": "Job not found"}), 404

    job["_id"] = str(job["_id"])
    logger.info(f"Job {job_id} retrieved for user: {current_user}")
    return jsonify(job), 200

@jobs_bp.route('/jobs/<job_id>', methods=['PUT'])
@jwt_required()
def update_job(job_id):
    data = request.get_json()
    current_user = get_jwt_identity()

    if data is None:
        logger.warning(f"Job update attempt with invalid input for user: {current_user}")
        return jsonify({"error": "Invalid input"}), 400

    update_fields = {}

    # Check to see which fields are present in the request and add them to the update_fields dictionary
    if "title" in data:
        update_fields["title"] = data["title"]
    
    if "company" in data:
        update_fields["company"] = data["company"]
    
    if "status" in data:
        VALID_STATUSES = ["Applied", "Interview", "Assessment", "Offer", "Rejected", "Withdrawn"]
        if data["status"] not in VALID_STATUSES:
            logger.warning(f"Job update attempt with invalid status for user: {current_user}")
            return jsonify({"error": "Invalid status value"}), 400
        
        else:
            update_fields["status"] = data["status"]
    
    if "notes" in data:
        update_fields["notes"] = data["notes"]
    
    if "location" in data:
        update_fields["location"] = data["location"]
    
    if "application_url" in data:
        update_fields["application_url"] = data["application_url"]

    # Update the job in the Mongo database and check if the job exists for the current user
    try:
        result = jobs_collection.update_one(
            {"_id": ObjectId(job_id), "username": current_user},
            {"$set": update_fields}
        )
    except Exception:
        logger.warning(f"Invalid job ID format: {job_id} for user: {current_user}")
        return jsonify({"error": "Invalid ID format"}), 400

    if result.matched_count == 0:
        logger.warning(f"Job {job_id} not found for user: {current_user}")
        return jsonify({"error": "Job not found"}), 404

    job = jobs_collection.find_one({"_id": ObjectId(job_id), "username": current_user})
    job["_id"] = str(job["_id"])

    logger.info(f"Job {job_id} updated for user: {current_user}")
    return jsonify(job), 200

@jobs_bp.route('/jobs/<job_id>', methods=['DELETE'])
@jwt_required()
def delete_job(job_id):
    current_user = get_jwt_identity()
    
    try:
        result = jobs_collection.delete_one({"_id": ObjectId(job_id), "username": current_user})
    except Exception:
        logger.warning(f"Invalid job ID format: {job_id} for user: {current_user}")
        return jsonify({"error": "Invalid ID format"}), 400

    if result.deleted_count == 0:
        logger.warning(f"Job {job_id} not found for user: {current_user}")
        return jsonify({"error": "Job not found"}), 404

    logger.info(f"Job {job_id} deleted for user: {current_user}")
    return jsonify({"message": "Job deleted"}), 200