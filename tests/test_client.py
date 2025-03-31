"""
Tests for the CatalystClient class.
"""

import json
import logging
import unittest
from datetime import datetime
from unittest.mock import ANY, MagicMock, patch

import requests
from requests.exceptions import RequestException

from python_catalyst.client import CatalystClient
from python_catalyst.enums import ObservableType, PostCategory, TLPLevel


class TestCatalystClient(unittest.TestCase):
    """
    Test suite for the CatalystClient class.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.api_key = "test_api_key"
        self.base_url = "https://test.api.com"
        self.client = CatalystClient(
            api_key=self.api_key,
            base_url=self.base_url,
            logger=logging.getLogger("test_logger"),
        )

    @patch("requests.Session.request")
    def test_handle_request_success(self, mock_request):
        """Test successful API request handling."""

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": "test_data"}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        result = self.client._handle_request(
            "GET", "/test/endpoint", {"param": "value"}
        )

        mock_request.assert_called_once_with(
            method="GET",
            url=f"{self.base_url}/test/endpoint",
            params={"param": "value"},
            json=None,
        )
        self.assertEqual(result, {"data": "test_data"})

    @patch("requests.Session.request")
    def test_handle_request_failure(self, mock_request):
        """Test handling of failed API requests."""
        mock_request.side_effect = RequestException("Test error")

        with self.assertRaises(RequestException):
            self.client._handle_request("GET", "/test/endpoint")

    @patch.object(CatalystClient, "_handle_request")
    def test_get_member_contents(self, mock_handle_request):
        """Test retrieving member contents."""
        mock_handle_request.return_value = {
            "results": [{"id": "123", "title": "Test Content"}]
        }
        test_datetime = datetime(2023, 1, 1, 12, 0, 0)

        result = self.client.get_member_contents(
            category=PostCategory.RESEARCH,
            tlp=[TLPLevel.AMBER],
            published_on_after=test_datetime,
            published_on_before=test_datetime,
            updated_on_after=test_datetime,
            search="test search",
            page=2,
            page_size=50,
            ordering="-updated_on",
        )

        mock_handle_request.assert_called_once_with(
            "GET",
            self.client.content_endpoint,
            params={
                "category": "RESEARCH",
                "tlp": "TLP:AMBER",
                "published_on_after": test_datetime.isoformat(),
                "published_on_before": test_datetime.isoformat(),
                "updated_on_after": test_datetime.isoformat(),
                "search": "test search",
                "page": 2,
                "page_size": 50,
                "ordering": "-updated_on",
            },
        )
        self.assertEqual(result, {"results": [{"id": "123", "title": "Test Content"}]})

    @patch.object(CatalystClient, "_handle_request")
    def test_get_member_content(self, mock_handle_request):
        """Test retrieving a specific member content by ID."""
        content_id = "test_id"
        mock_handle_request.return_value = {"id": content_id, "title": "Test Content"}

        result = self.client.get_member_content(content_id)

        mock_handle_request.assert_called_once_with(
            "GET", f"{self.client.content_endpoint}{content_id}/"
        )
        self.assertEqual(result, {"id": content_id, "title": "Test Content"})

    @patch.object(CatalystClient, "get_member_contents")
    def test_get_all_member_contents(self, mock_get_member_contents):
        """Test retrieving all member contents with pagination handling."""
        mock_get_member_contents.side_effect = [
            {"count": 150, "next": "next_url", "results": [{"id": "1"}, {"id": "2"}]},
            {"count": 150, "next": "next_url_2", "results": [{"id": "3"}, {"id": "4"}]},
            {"count": 150, "next": None, "results": [{"id": "5"}]},
        ]

        result = self.client.get_all_member_contents(
            category=PostCategory.RESEARCH,
            tlp=[TLPLevel.AMBER],
            page_size=2,
            max_results=5,
        )

        self.assertEqual(mock_get_member_contents.call_count, 3)
        self.assertEqual(len(result), 5)
        self.assertEqual(
            result, [{"id": "1"}, {"id": "2"}, {"id": "3"}, {"id": "4"}, {"id": "5"}]
        )

    @patch.object(CatalystClient, "get_all_member_contents")
    def test_get_updated_member_contents(self, mock_get_all_member_contents):
        """Test retrieving updated member contents since a specific date."""
        since_date = datetime(2023, 1, 1, 12, 0, 0)
        mock_get_all_member_contents.return_value = [{"id": "1"}, {"id": "2"}]

        result = self.client.get_updated_member_contents(
            since=since_date, category=PostCategory.DISCOVERY, tlp=[TLPLevel.GREEN]
        )

        mock_get_all_member_contents.assert_called_once_with(
            category=PostCategory.DISCOVERY,
            tlp=[TLPLevel.GREEN],
            updated_on_after=since_date,
            page_size=100,
            max_results=None,
            ordering="-updated_on",
        )
        self.assertEqual(result, [{"id": "1"}, {"id": "2"}])

    @patch.object(CatalystClient, "_get_all_references_for_post")
    def test_extract_entities_from_member_content(self, mock_get_all_references):
        """Test extracting entities from member content."""
        content_id = "test_id"
        mock_references = [
            {
                "entity_type": "malware",
                "entity": "m1",
                "value": "Malware1",
                "context": "Malware context",
            },
            {
                "entity_type": "threat_actor",
                "entity": "ta1",
                "value": "ThreatActor1",
                "context": "Threat actor context",
            },
            {
                "entity_type": "observable",
                "entity": "obs1",
                "value": "192.168.1.1",
                "value_type": "IP_ADDRESS",
                "context": "Observable context",
            },
        ]
        mock_get_all_references.return_value = mock_references

        result = self.client.extract_entities_from_member_content(content_id)

        mock_get_all_references.assert_called_once_with(content_id)
        self.assertIn("malware", result)
        self.assertIn("threat_actor", result)
        self.assertIn("observable", result)
        self.assertEqual(len(result["malware"]), 1)
        self.assertEqual(len(result["threat_actor"]), 1)
        self.assertEqual(len(result["observable"]), 1)
        self.assertEqual(result["malware"][0]["id"], "m1")
        self.assertEqual(result["malware"][0]["value"], "Malware1")
        self.assertEqual(result["observable"][0]["type"], "IP_ADDRESS")


if __name__ == "__main__":
    unittest.main()
