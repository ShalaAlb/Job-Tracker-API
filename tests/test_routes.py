from datetime import datetime, timezone
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import bcrypt
import pytest
from bson import ObjectId
from flask_jwt_extended import create_access_token
from ratelimit import decorators as rate_limit_decorators

import job_tracker.app as app_module
from job_tracker.auth import routes as auth_routes
from job_tracker.jobs import routes as jobs_routes


def _rate_limit_state(view):
    limited_view = view.__wrapped__
    for cell in limited_view.__closure__ or ():
        state = cell.cell_contents
        if state.__class__.__name__ == "RateLimitDecorator":
            return state
    pytest.fail(f"No rate-limit state found for {view.__name__}")


@pytest.fixture(autouse=True)
def isolate_auth_rate_limits(monkeypatch):
    monkeypatch.setenv(
        "JWT_SECRET_KEY",
        "test-jwt-secret-key-for-pytest-with-32-bytes",
    )
    for view in (auth_routes.register, auth_routes.login):
        state = _rate_limit_state(view)
        state.num_calls = 0
        state.last_reset = state.clock()


@pytest.fixture
def auth_headers(app):
    with app.app_context():
        token = create_access_token(identity="alice")
    return {"Authorization": f"Bearer {token}"}


def test_jobs_requires_authentication(client):
    response = client.get("/jobs")

    assert response.status_code == 401

def test_jobs_rejects_invalid_token(client):
    response = client.get(
        "/jobs",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 422

def test_register_success(client, monkeypatch):
    users = MagicMock()
    users.find_one.return_value = None
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/register",
        json={"username": "alice", "password": "Aa1!correcthorse"},
    )

    assert response.status_code == 201
    assert response.get_json() == {"message": "User registered"}

    stored_user = users.insert_one.call_args.args[0]
    assert stored_user["username"] == "alice"
    assert stored_user["password"] != b"Aa1!correcthorse"
    assert bcrypt.checkpw(
        b"Aa1!correcthorse",
        stored_user["password"],
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": "alice"},
        {"password": "password"},
    ],
)
def test_register_rejects_missing_fields(client, monkeypatch, payload):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post("/register", json=payload)

    assert response.status_code == 400
    users.insert_one.assert_not_called()


def test_register_rejects_duplicate_username(client, monkeypatch):
    users = MagicMock()
    users.find_one.return_value = {"username": "alice"}
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/register",
        json={"username": "alice", "password": "Aa1!password"},
    )

    assert response.status_code == 409
    users.insert_one.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        ["not", "an", "object"],
        "not-an-object",
        7,
    ],
)
@pytest.mark.parametrize("endpoint", ["/register", "/login"])
def test_auth_rejects_non_object_json(client, monkeypatch, endpoint, payload):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(endpoint, json=payload)

    assert response.status_code == 400
    users.find_one.assert_not_called()
    users.insert_one.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        {"username": 123, "password": "Aa1!password"},
        {"username": "alice", "password": 123},
        {"username": ["alice"], "password": "Aa1!password"},
        {"username": "alice", "password": ["Aa1!password"]},
    ],
)
def test_register_rejects_non_string_fields(client, monkeypatch, payload):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post("/register", json=payload)

    assert response.status_code == 400
    users.find_one.assert_not_called()
    users.insert_one.assert_not_called()


@pytest.mark.parametrize(
    "password",
    [
        "Aa1!xxx",
        "aa1!xxxx",
        "AA1!XXXX",
        "Aa!!xxxx",
        "Aa11xxxx",
        "Aa1#xxxx",
    ],
)
def test_register_rejects_passwords_outside_policy(
    client, monkeypatch, password
):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/register",
        json={"username": "alice", "password": password},
    )

    assert response.status_code == 400
    users.find_one.assert_not_called()
    users.insert_one.assert_not_called()


@pytest.mark.parametrize("password", ["Aa1!xxxx", "Aa1!" + "x" * 68])
def test_register_accepts_password_length_boundaries(client, monkeypatch, password):
    users = MagicMock()
    users.find_one.return_value = None
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/register",
        json={"username": "alice", "password": password},
    )

    assert response.status_code == 201
    assert bcrypt.checkpw(
        password.encode("utf-8"),
        users.insert_one.call_args.args[0]["password"],
    )


def test_register_rejects_password_over_bcrypt_limit(client, monkeypatch):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/register",
        json={"username": "alice", "password": "Aa1!" + "x" * 69},
    )

    assert response.status_code == 400
    users.find_one.assert_not_called()
    users.insert_one.assert_not_called()


def test_login_success_returns_usable_token(client, monkeypatch):
    password_hash = bcrypt.hashpw(b"correct password", bcrypt.gensalt())
    users = MagicMock()
    users.find_one.return_value = {
        "username": "alice",
        "password": password_hash,
    }
    cursor = MagicMock()
    cursor.sort.return_value = cursor
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.__iter__.return_value = iter([])
    jobs = MagicMock()
    jobs.find.return_value = cursor
    monkeypatch.setattr(auth_routes, "users_collection", users)
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.post(
        "/login",
        json={"username": "alice", "password": "correct password"},
    )

    assert response.status_code == 200
    token = response.get_json()["access_token"]
    protected_response = client.get(
        "/jobs",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert protected_response.status_code == 200


@pytest.mark.parametrize(
    ("stored_user", "payload"),
    [
        (None, {"username": "missing", "password": "password"}),
        (
            {
                "username": "alice",
                "password": bcrypt.hashpw(b"correct password", bcrypt.gensalt()),
            },
            {"username": "alice", "password": "wrong password"},
        ),
    ],
)
def test_login_rejects_invalid_credentials(client, monkeypatch, stored_user, payload):
    users = MagicMock()
    users.find_one.return_value = stored_user
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post("/login", json=payload)

    assert response.status_code == 401
    assert "access_token" not in response.get_json()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"password": "Aa1!password"},
        {"username": "alice"},
        {"username": "", "password": "Aa1!password"},
        {"username": "alice", "password": ""},
        {"username": 123, "password": "Aa1!password"},
        {"username": "alice", "password": 123},
    ],
)
def test_login_rejects_missing_or_non_string_fields(client, monkeypatch, payload):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post("/login", json=payload)

    assert response.status_code == 400
    users.find_one.assert_not_called()


def test_login_rejects_password_over_bcrypt_limit(client, monkeypatch):
    users = MagicMock()
    monkeypatch.setattr(auth_routes, "users_collection", users)

    response = client.post(
        "/login",
        json={"username": "alice", "password": "A" * 73},
    )

    assert response.status_code == 400
    users.find_one.assert_not_called()


def test_login_uses_same_error_for_unknown_user_and_wrong_password(
    client, monkeypatch
):
    users = MagicMock()
    users.find_one.side_effect = [
        None,
        {
            "username": "alice",
            "password": bcrypt.hashpw(b"correct password", bcrypt.gensalt()),
        },
    ]
    monkeypatch.setattr(auth_routes, "users_collection", users)

    unknown_user = client.post(
        "/login",
        json={"username": "unknown", "password": "wrong password"},
    )
    wrong_password = client.post(
        "/login",
        json={"username": "alice", "password": "wrong password"},
    )

    assert unknown_user.status_code == wrong_password.status_code == 401
    assert unknown_user.get_json() == wrong_password.get_json()


def test_login_rate_limit_waits_before_retrying(client, monkeypatch):
    users = MagicMock()
    users.find_one.return_value = None
    monkeypatch.setattr(auth_routes, "users_collection", users)

    state = _rate_limit_state(auth_routes.login)
    current_time = [state.clock()]
    monkeypatch.setattr(state, "clock", lambda: current_time[0])
    state.last_reset = current_time[0]
    sleep_periods = []

    # Advance the decorator's clock instead of waiting a real minute in the test.
    def advance_clock(period):
        sleep_periods.append(period)
        current_time[0] += period

    monkeypatch.setattr(rate_limit_decorators.time, "sleep", advance_clock)

    responses = [
        client.post(
            "/login",
            json={"username": "missing", "password": "Aa1!password"},
        )
        for _ in range(6)
    ]

    assert all(response.status_code == 401 for response in responses)
    assert len(sleep_periods) == 1
    assert sleep_periods[0] == pytest.approx(60)
    assert users.find_one.call_count == 6


def test_login_does_not_log_password_or_request_body(client, monkeypatch, caplog):
    users = MagicMock()
    users.find_one.return_value = None
    monkeypatch.setattr(auth_routes, "users_collection", users)
    secret_password = "Sensitive-A1!Password"

    with caplog.at_level(logging.INFO):
        response = client.post(
            "/login",
            json={"username": "alice", "password": secret_password},
        )

    assert response.status_code == 401
    # Credentials must never appear in request or authentication logs.
    assert secret_password not in caplog.text
    assert '"password"' not in caplog.text


def test_create_app_requires_jwt_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
        app_module.create_app()


def test_create_job_success(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    jobs = MagicMock()
    jobs.insert_one.return_value = SimpleNamespace(inserted_id=job_id)
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.post(
        "/jobs",
        json={"title": "Engineer", "company": "Example Inc"},
        headers=auth_headers,
    )

    assert response.status_code == 201
    job = response.get_json()
    assert job["_id"] == str(job_id)
    assert job["title"] == "Engineer"
    assert job["company"] == "Example Inc"
    assert job["status"] == "Applied"
    assert job["username"] == "alice"

    stored_job = jobs.insert_one.call_args.args[0]
    assert stored_job["username"] == "alice"
    assert stored_job["date_applied"].tzinfo == timezone.utc


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": "Engineer"},
        {"company": "Example Inc"},
    ],
)
def test_create_job_rejects_missing_required_fields(
    client, auth_headers, monkeypatch, payload
):
    jobs = MagicMock()
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.post("/jobs", json=payload, headers=auth_headers)

    assert response.status_code == 400
    jobs.insert_one.assert_not_called()


def test_get_jobs_returns_only_current_users_jobs(client, auth_headers, monkeypatch):
    job = {
        "_id": ObjectId(),
        "username": "alice",
        "title": "Engineer",
        "date_applied": datetime.now(timezone.utc),
    }
    cursor = MagicMock()
    cursor.sort.return_value = cursor
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.__iter__.return_value = iter([job])

    jobs = MagicMock()
    jobs.find.return_value = cursor
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get("/jobs", headers=auth_headers)

    assert response.status_code == 200
    assert [item["title"] for item in response.get_json()] == ["Engineer"]
    jobs.find.assert_called_once_with({"username": "alice"})
    cursor.sort.assert_called_once_with("date_applied", -1)
    cursor.skip.assert_called_once_with(0)
    cursor.limit.assert_called_once_with(10)


def test_get_jobs_applies_filters_order_and_pagination(
    client, auth_headers, monkeypatch
):
    cursor = MagicMock()
    cursor.sort.return_value = cursor
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.__iter__.return_value = iter([])
    jobs = MagicMock()
    jobs.find.return_value = cursor
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get(
        "/jobs?status=Interview&company=Example&location=Remote"
        "&resume=backend&sort=company&order=asc&page=2&limit=5",
        headers=auth_headers,
    )

    assert response.status_code == 200
    jobs.find.assert_called_once_with(
        {
            "username": "alice",
            "status": "Interview",
            "company": "Example",
            "location": "Remote",
            "resume": "backend",
        }
    )
    cursor.sort.assert_called_once_with("company", 1)
    cursor.skip.assert_called_once_with(5)
    cursor.limit.assert_called_once_with(5)


@pytest.mark.parametrize(
    "query_string",
    [
        "?sort=password",
        "?order=sideways",
        "?page=0",
        "?limit=0",
        "?page=not-a-number",
    ],
)
def test_get_jobs_rejects_invalid_query_parameters(
    client, auth_headers, monkeypatch, query_string
):
    jobs = MagicMock()
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get(f"/jobs{query_string}", headers=auth_headers)

    assert response.status_code == 400
    jobs.find.assert_not_called()


def test_get_job_returns_own_job(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    job = {"_id": job_id, "username": "alice", "title": "Engineer"}
    jobs = MagicMock()
    jobs.find_one.return_value = job
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get(f"/jobs/{job_id}", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json()["_id"] == str(job_id)
    jobs.find_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"}
    )


def test_get_job_rejects_invalid_id(client, auth_headers, monkeypatch):
    jobs = MagicMock()
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get("/jobs/not-an-object-id", headers=auth_headers)

    assert response.status_code == 400
    jobs.find_one.assert_not_called()


def test_user_cannot_read_another_users_job(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    jobs = MagicMock()
    jobs.find_one.return_value = None
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.get(f"/jobs/{job_id}", headers=auth_headers)

    assert response.status_code == 404
    jobs.find_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"}
    )


def test_update_job_success_updates_allowed_fields(
    client, auth_headers, monkeypatch
):
    job_id = ObjectId()
    updated_job = {
        "_id": job_id,
        "username": "alice",
        "title": "Senior Engineer",
        "status": "Interview",
    }
    jobs = MagicMock()
    jobs.update_one.return_value = SimpleNamespace(matched_count=1)
    jobs.find_one.return_value = updated_job
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.put(
        f"/jobs/{job_id}",
        json={"title": "Senior Engineer", "status": "Interview"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.get_json()["title"] == "Senior Engineer"
    assert response.get_json()["status"] == "Interview"
    jobs.update_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"},
        {"$set": {"title": "Senior Engineer", "status": "Interview"}},
    )


def test_update_job_rejects_invalid_status_without_updating(
    client, auth_headers, monkeypatch
):
    jobs = MagicMock()
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.put(
        f"/jobs/{ObjectId()}",
        json={"status": "In progress"},
        headers=auth_headers,
    )

    assert response.status_code == 400
    jobs.update_one.assert_not_called()


def test_user_cannot_update_another_users_job(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    jobs = MagicMock()
    jobs.update_one.return_value = SimpleNamespace(matched_count=0)
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.put(
        f"/jobs/{job_id}",
        json={"title": "Changed title"},
        headers=auth_headers,
    )

    assert response.status_code == 404
    jobs.update_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"},
        {"$set": {"title": "Changed title"}},
    )
    jobs.find_one.assert_not_called()


def test_delete_job_success(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    jobs = MagicMock()
    jobs.delete_one.return_value = SimpleNamespace(deleted_count=1)
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.delete(f"/jobs/{job_id}", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json() == {"message": "Job deleted"}
    jobs.delete_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"}
    )


def test_user_cannot_delete_another_users_job(client, auth_headers, monkeypatch):
    job_id = ObjectId()
    jobs = MagicMock()
    jobs.delete_one.return_value = SimpleNamespace(deleted_count=0)
    monkeypatch.setattr(jobs_routes, "jobs_collection", jobs)

    response = client.delete(f"/jobs/{job_id}", headers=auth_headers)

    assert response.status_code == 404
    jobs.delete_one.assert_called_once_with(
        {"_id": job_id, "username": "alice"}
    )