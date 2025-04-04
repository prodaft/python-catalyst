"""
Pytest configuration file for the PRODAFT CATALYST API client package.
"""

import logging
import os

import pytest


def pytest_addoption(parser):
    """Add command line options to pytest."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that require API credentials",
    )


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "integration: mark test as requiring API credentials"
    )


def pytest_collection_modifyitems(config, items):
    """Modify collected test items."""
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Need --run-integration option to run"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


@pytest.fixture
def api_key():
    """Return the API key from environment variables."""
    return os.environ.get("CATALYST_API_KEY", "dummy_api_key_for_tests")


@pytest.fixture
def test_logger():
    """Return a logger for tests."""
    logger = logging.getLogger("test_logger")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    return logger
