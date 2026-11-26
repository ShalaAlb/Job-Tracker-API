# tests/conftest.py
import pytest
from job_tracker.app import create_app 

@pytest.fixture
def app():
    # Initialize the app with specific test configurations
    app = create_app()
    yield app

@pytest.fixture
def client(app):
    # Returns a test client that can make HTTP requests
    return app.test_client()