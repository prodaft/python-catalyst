"""
Integration tests for the PRODAFT CATALYST API client package.

Note: These tests require actual API credentials and will call the real API.
To run these tests, you need to set the CATALYST_API_KEY environment variable.
"""

import os
import unittest
from datetime import datetime, timedelta, timezone

import pytest

from python_catalyst.client import CatalystClient
from python_catalyst.enums import ObservableType, PostCategory, TLPLevel


@pytest.mark.integration
class TestIntegration(unittest.TestCase):
    """
    Integration test suite for the CATALYST API client.
    These tests interact with the actual API and require API credentials.
    """

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures that are used by all test methods."""
        # Get the API key from the environment
        cls.api_key = os.environ.get("CATALYST_API_KEY")
        if not cls.api_key:
            raise unittest.SkipTest("CATALYST_API_KEY environment variable not set")

        cls.client = CatalystClient(api_key=cls.api_key)

    def test_get_member_contents(self):
        """Test retrieving member contents from the actual API."""
        result = self.client.get_member_contents(
            category=PostCategory.RESEARCH, page=1, page_size=5
        )

        self.assertIn("count", result)
        self.assertIn("results", result)
        self.assertIsInstance(result["results"], list)

        if result["results"]:
            first_result = result["results"][0]
            self.assertIn("id", first_result)
            self.assertIn("title", first_result)
            self.assertIn("summary", first_result)

    def test_get_updated_member_contents(self):
        """Test retrieving updated member contents."""
        # Get content updated in the last 30 days
        since = datetime.now(timezone.utc) - timedelta(days=30)

        result = self.client.get_updated_member_contents(since=since, max_results=5)

        self.assertIsInstance(result, list)
        self.assertLessEqual(len(result), 5)

        if result:
            first_result = result[0]
            self.assertIn("id", first_result)
            self.assertIn("title", first_result)
            self.assertIn("updated_on", first_result)

            # Verify the updated_on date is after our since date
            updated_on = datetime.fromisoformat(
                first_result["updated_on"].replace("Z", "+00:00")
            )
            self.assertGreaterEqual(updated_on, since)

    def test_extract_entities_from_member_content(self):
        """Test extracting entities from a member content."""
        contents = self.client.get_member_contents(page_size=1)

        if not contents["results"]:
            self.skipTest("No content available to extract entities from")

        content_id = contents["results"][0]["id"]

        # Extract entities
        entities = self.client.extract_entities_from_member_content(content_id)

        self.assertIsInstance(entities, dict)

        expected_entity_types = [
            "malware",
            "organization",
            "threatactor",
            "vulnerability",
            "campaign",
            "tool",
            "indicator",
        ]

        # Check that at least one expected entity type is present
        found_entity_types = False
        for entity_type in expected_entity_types:
            if entity_type in entities:
                found_entity_types = True
                self.assertIsInstance(entities[entity_type], list)

        self.assertTrue(
            found_entity_types, "No expected entity types found in the response"
        )


if __name__ == "__main__":
    unittest.main()
