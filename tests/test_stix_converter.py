"""
Tests for the StixConverter class.
"""

import unittest
import uuid
from unittest.mock import MagicMock, patch

import stix2

from python_catalyst.enums import ObservableType, TLPLevel
from python_catalyst.stix_converter import StixConverter


class TestStixConverter(unittest.TestCase):
    """
    Test suite for the StixConverter class.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.converter = StixConverter(
            author_name="Test Organization",
            tlp_level="tlp:green",
            create_observables=True,
            create_indicators=True,
        )

    def test_init(self):
        """Test StixConverter initialization."""
        self.assertEqual(self.converter.author_name, "Test Organization")
        self.assertEqual(self.converter.tlp_level, "tlp:green")
        self.assertTrue(self.converter.create_observables)
        self.assertTrue(self.converter.create_indicators)
        self.assertIsInstance(self.converter.identity, stix2.Identity)
        self.assertEqual(self.converter.identity.name, "Test Organization")
        self.assertEqual(self.converter.identity.identity_class, "organization")

    def test_create_tlp_marking(self):
        """Test creating TLP marking definitions."""
        # Test default marking (from setUp)
        self.assertEqual(self.converter.tlp_marking.definition.tlp, "green")

        # Test different TLP levels
        white_marking = self.converter._create_tlp_marking("tlp:white")
        self.assertEqual(white_marking.definition.tlp, "white")

        amber_marking = self.converter._create_tlp_marking("tlp:amber")
        self.assertEqual(amber_marking.definition.tlp, "amber")

        red_marking = self.converter._create_tlp_marking("tlp:red")
        self.assertEqual(red_marking.definition.tlp, "red")

    def test_create_external_reference(self):
        """Test creating external references with caching."""
        # Test creating a reference
        ref1 = self.converter._create_external_reference("Test Source", "ID123")
        self.assertEqual(ref1.source_name, "Test Source")
        self.assertEqual(ref1.external_id, "ID123")

        # Test caching - should return the same object
        ref2 = self.converter._create_external_reference("Test Source", "ID123")
        self.assertIs(ref1, ref2)

        # Test creating a different reference
        ref3 = self.converter._create_external_reference("Test Source", "ID456")
        self.assertIsNot(ref1, ref3)
        self.assertEqual(ref3.external_id, "ID456")

        # Test CATALYST specific reference for reports
        report_ref = self.converter._create_external_reference(
            "PRODAFT CATALYST", "POST123", True
        )
        self.assertEqual(report_ref.source_name, "PRODAFT CATALYST")
        self.assertEqual(report_ref.url, "https://catalyst.prodaft.com/report/POST123/")

    def test_get_post_reference(self):
        """Test getting a cached STIX ID for a post reference."""
        # Test creating a post reference
        post_id = "post123"
        ref1 = self.converter.get_post_reference(post_id)
        expected_id = f"report--{uuid.uuid5(uuid.NAMESPACE_URL, post_id)}"
        self.assertEqual(ref1, expected_id)

        # Test caching - should return the same ID
        ref2 = self.converter.get_post_reference(post_id)
        self.assertEqual(ref1, ref2)

    @patch.object(StixConverter, "_create_tlp_marking")
    def test_create_relationship(self, mock_create_tlp_marking):
        """Test creating STIX relationships."""
        mock_create_tlp_marking.return_value = stix2.TLP_GREEN
        valid_uuid = "84c0471a-9448-48af-9c50-7f5b3a6a8a5b"
        source_ref = f"malware--{valid_uuid}"
        target_ref = f"identity--{valid_uuid}"
        relationship_type = "targets"

        with patch("stix2.Relationship") as mock_relationship:
            mock_relationship.return_value = MagicMock()

            relationship = self.converter.create_relationship(
                source_ref, target_ref, relationship_type
            )

            mock_relationship.assert_called_once()
            call_kwargs = mock_relationship.call_args[1]
            self.assertEqual(call_kwargs["source_ref"], source_ref)
            self.assertEqual(call_kwargs["target_ref"], target_ref)
            self.assertEqual(call_kwargs["relationship_type"], relationship_type)

    def test_create_ip_observable(self):
        """Test creating IP address observables."""
        # Test IPv4
        ipv4 = self.converter._create_ip_observable("192.168.1.1")
        self.assertIsInstance(ipv4, stix2.IPv4Address)
        self.assertEqual(ipv4.value, "192.168.1.1")

        # Test IPv6
        ipv6 = self.converter._create_ip_observable(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        )
        self.assertIsInstance(ipv6, stix2.IPv6Address)
        self.assertEqual(ipv6.value, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_create_domain_observable(self):
        """Test creating domain name observables."""
        domain = self.converter._create_domain_observable("example.com")
        self.assertIsInstance(domain, stix2.DomainName)
        self.assertEqual(domain.value, "example.com")

    def test_create_url_observable(self):
        """Test creating URL observables."""
        # Test URL
        url = self.converter._create_url_observable("https://example.com/path")
        self.assertIsInstance(url, stix2.URL)
        self.assertEqual(url.value, "https://example.com/path")

    def test_create_email_observable(self):
        """Test creating email address observables."""
        # Test email
        email = self.converter._create_email_observable("user@example.com")
        self.assertIsInstance(email, stix2.EmailAddress)
        self.assertEqual(email.value, "user@example.com")

    def test_create_file_observable(self):
        """Test creating file observables."""
        # Test MD5
        md5 = self.converter._create_file_observable(
            "098f6bcd4621d373cade4e832627b4f6", "MD5"
        )
        self.assertIsInstance(md5, stix2.File)
        self.assertEqual(md5.hashes["MD5"], "098f6bcd4621d373cade4e832627b4f6")

        # Test SHA-1
        sha1 = self.converter._create_file_observable(
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "SHA-1"
        )
        self.assertIsInstance(sha1, stix2.File)
        self.assertEqual(
            sha1.hashes["SHA-1"], "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        )

        # Test SHA-256
        sha256 = self.converter._create_file_observable(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "SHA-256",
        )
        self.assertIsInstance(sha256, stix2.File)
        self.assertEqual(
            sha256.hashes["SHA-256"],
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )

    def test_convert_observable_to_stix(self):
        """Test converting observables to STIX format."""
        observable_data = {
            "id": "obs123",
            "value": "192.168.1.1",
            "type": ObservableType.IP_ADDRESS.value,
        }

        with patch.object(StixConverter, "convert_observable_to_stix") as mock_convert:
            mock_observable = stix2.IPv4Address(value="192.168.1.1")
            mock_indicator = stix2.Indicator(
                name="192.168.1.1",
                pattern="[ipv4-addr:value = '192.168.1.1']",
                pattern_type="stix",
            )
            mock_convert.return_value = (mock_observable, [], mock_indicator)

            (
                observable,
                relationships,
                indicator,
            ) = self.converter.convert_observable_to_stix(observable_data)

            self.assertEqual(observable, mock_observable)
            self.assertEqual(indicator, mock_indicator)
            mock_convert.assert_called_once_with(observable_data)

    def test_create_report(self):
        """Test creating STIX Reports."""
        content_id = "report123"
        title = "Test Report"
        description = "Test Description"
        published = "2023-01-01T12:00:00Z"
        modified = "2023-01-02T12:00:00Z"
        valid_uuid = "84c0471a-9448-48af-9c50-7f5b3a6a8a5b"
        object_refs = [f"malware--{valid_uuid}", f"indicator--{valid_uuid}"]

        # Mock Report creation
        with patch("stix2.Report") as mock_report:
            mock_report_obj = MagicMock()
            mock_report_obj.name = title
            mock_report_obj.description = description
            mock_report_obj.published = published
            mock_report_obj.modified = modified
            mock_report_obj.object_refs = object_refs
            mock_report_obj.created_by_ref = self.converter.identity.id
            mock_report_obj.object_marking_refs = [self.converter.tlp_marking.id]
            mock_report.return_value = mock_report_obj

            report = self.converter.create_report(
                content_id=content_id,
                title=title,
                description=description,
                published=published,
                modified=modified,
                object_refs=object_refs,
            )

            self.assertEqual(report.name, title)
            self.assertEqual(report.description, description)
            self.assertEqual(report.published, published)
            self.assertEqual(report.modified, modified)
            self.assertEqual(report.object_refs, object_refs)
            self.assertEqual(report.created_by_ref, self.converter.identity.id)
            self.assertEqual(
                report.object_marking_refs, [self.converter.tlp_marking.id]
            )


if __name__ == "__main__":
    unittest.main()
