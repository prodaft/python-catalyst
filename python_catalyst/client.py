"""Client for the CATALYST API."""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests
import stix2
from requests.exceptions import RequestException

from .enums import PostCategory, TLPLevel


class CatalystClient:
    """Client for the CATALYST API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://prod.blindspot.prodaft.com/api",
        proxy_url: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        create_observables: bool = True,
        create_indicators: bool = True,
    ):
        """
        Initialize the CATALYST API client.

        Args:
            api_key: The API key for authentication
            base_url: The base URL for the API
            proxy_url: Optional proxy URL
            logger: Optional logger instance
            create_observables: Whether to create observables
            create_indicators: Whether to create indicators
        """
        self.api_key = api_key
        self.catalyst_authenticated = True if self.api_key else False
        self.base_url = base_url.rstrip("/")
        self.logger = logger or logging.getLogger(__name__)
        self.content_endpoint = (
            "/posts/member-contents/"
            if self.catalyst_authenticated
            else "/posts/guest-contents/"
        )

        self.session = requests.Session()
        if proxy_url:
            self.session.proxies = {"http": proxy_url, "https": proxy_url}

        self.session.headers.update(
            {
                "Authorization": (
                    f"Token {self.api_key}" if self.catalyst_authenticated else None
                ),
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        # extra config params
        self.create_observables = create_observables
        self.create_indicators = create_indicators

    def _handle_request(
        self, method: str, endpoint: str, params: Dict = None, data: Dict = None
    ) -> Dict:
        """
        Handle HTTP requests to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            params: URL parameters
            data: Request payload

        Returns:
            Response data as dictionary

        Raises:
            RequestException: If the request fails
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = self.session.request(
                method=method, url=url, params=params, json=data
            )

            response.raise_for_status()
            return response.json()
        except RequestException as e:
            self.logger.error(f"Request error: {str(e)}")
            raise

    def get_member_contents(
        self,
        category: Optional[PostCategory] = None,
        tlp: Optional[List[TLPLevel]] = None,
        published_on_after: Optional[datetime] = None,
        published_on_before: Optional[datetime] = None,
        updated_on_after: Optional[datetime] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
        ordering: Optional[str] = None,
    ) -> Dict:
        """
        Get member contents from the CATALYST API.

        Args:
            category: Category of the post to filter by
            tlp: List of TLP classifications to filter by
            published_on_after: Filter for posts published after this datetime
            published_on_before: Filter for posts published before this datetime
            updated_on_after: Filter for posts updated after this datetime
            search: Keyword search term
            page: Page number for pagination
            page_size: Number of results per page
            ordering: Field to order results by (e.g., 'updated_on', '-updated_on' for descending)

        Returns:
            Dictionary containing member contents results
        """
        params = {"page": page, "page_size": page_size}

        if category:
            params["category"] = (
                category.value if isinstance(category, PostCategory) else category
            )

        if tlp:
            if len(tlp) > 0:
                first_tlp = tlp[0]
                params["tlp"] = (
                    first_tlp.value if isinstance(first_tlp, TLPLevel) else first_tlp
                )
                if len(tlp) > 1:
                    self.logger.debug(
                        f"Multiple TLP values provided but API only supports one. Using: {params['tlp']}"
                    )

        if published_on_after:
            params["published_on_after"] = published_on_after.isoformat()

        if published_on_before:
            params["published_on_before"] = published_on_before.isoformat()

        if updated_on_after:
            params["updated_on_after"] = updated_on_after.isoformat()

        if search:
            params["search"] = search

        if ordering:
            params["ordering"] = ordering

        return self._handle_request("GET", self.content_endpoint, params=params)

    def get_member_content(self, content_id: str) -> Dict:
        """
        Get details for a specific member content by ID.

        Args:
            content_id: The ID of the member content

        Returns:
            Member content details dictionary
        """
        return self._handle_request("GET", f"{self.content_endpoint}{content_id}/")

    def get_all_member_contents(
        self,
        category: Optional[PostCategory] = None,
        tlp: Optional[List[TLPLevel]] = None,
        published_on_after: Optional[datetime] = None,
        published_on_before: Optional[datetime] = None,
        updated_on_after: Optional[datetime] = None,
        search: Optional[str] = None,
        page_size: int = 100,
        max_results: Optional[int] = None,
        ordering: str = "-updated_on",  # Default to newest updates first
    ) -> List[Dict]:
        """
        Get all member contents by automatically handling pagination.

        Args:
            category: Category of the post to filter by
            tlp: List of TLP classifications to filter by
            published_on_after: Filter for posts published after this datetime
            published_on_before: Filter for posts published before this datetime
            updated_on_after: Filter for posts updated after this datetime
            search: Keyword search term
            page_size: Number of results per page
            max_results: Maximum number of results to return (None for all)
            ordering: Field to order results by

        Returns:
            List of all member content dictionaries
        """
        results = []
        page = 1
        more_pages = True

        while more_pages:
            response = self.get_member_contents(
                category=category,
                tlp=tlp,
                published_on_after=published_on_after,
                published_on_before=published_on_before,
                updated_on_after=updated_on_after,
                search=search,
                page=page,
                page_size=page_size,
                ordering=ordering,
            )

            results.extend(response.get("results", []))

            if max_results and len(results) >= max_results:
                return results[:max_results]

            if response.get("next"):
                page += 1
            else:
                more_pages = False

        return results

    def get_updated_member_contents(
        self,
        since: datetime,
        category: Optional[PostCategory] = None,
        tlp: Optional[List[TLPLevel]] = None,
        page_size: int = 100,
        max_results: Optional[int] = None,
    ) -> List[Dict]:
        """
        Get member contents that have been updated since a specific datetime.

        Args:
            since: Datetime to filter posts updated after
            category: Category of the post to filter by
            tlp: List of TLP classifications to filter by
            page_size: Number of results per page
            max_results: Maximum number of results to return (None for all)

        Returns:
            List of updated member content dictionaries
        """
        if self.logger:
            self.logger.debug(
                f"Fetching member contents updated since: {since.isoformat()}"
            )

        contents = self.get_all_member_contents(
            category=category,
            tlp=tlp,
            updated_on_after=since,
            page_size=page_size,
            max_results=max_results,
            ordering="-updated_on",
        )

        if self.logger:
            self.logger.debug(
                f"Found {len(contents)} member contents updated since {since.isoformat()}"
            )

        return contents

    def extract_entities_from_member_content(
        self, content_id: str
    ) -> Dict[str, List[Dict]]:
        """
        Extract all types of entities from member content by fetching all references.

        Args:
            content_id: ID of the member content to extract entities from

        Returns:
            Dictionary mapping entity types to lists of entity objects
        """
        if self.logger:
            self.logger.info(f"Extracting all entities from post with ID: {content_id}")

        self.logger.info(f"Extracting all entities from post with ID: {content_id}")
        entities = {}

        all_references = self._get_all_references_for_post(content_id)

        processed_entities = {}
        entity_count = 0

        if all_references:
            for reference in all_references:
                if "entity_type" in reference and "entity" in reference:
                    entity_type = reference.get("entity_type", "").lower()
                    entity_id = reference.get("entity")
                    entity_value = reference.get("value")

                    if entity_type and entity_id and entity_value:
                        entity_key = f"{entity_type}:{entity_value}"  # noqa: E231

                        if entity_key in processed_entities:
                            continue

                        processed_entities[entity_key] = True
                        entity_count += 1

                        entity_obj = {
                            "id": entity_id,
                            "value": entity_value,
                            "entity_type": entity_type,
                        }

                        if entity_type == "observable":
                            entity_obj["type"] = reference.get("value_type")

                        if "context" in reference:
                            entity_obj["context"] = reference.get("context")

                        if entity_type in entities:
                            entities[entity_type].append(entity_obj)
                        else:
                            if entity_type not in entities:
                                entities[entity_type] = []
                            entities[entity_type].append(entity_obj)

        if self.logger:
            self.logger.info(
                f"Extracted {entity_count} unique entities from post: {content_id}"  # noqa: E221
            )
            for entity_type, entities_list in entities.items():
                self.logger.debug(
                    f"  - {len(entities_list)} {entity_type} entities"  # noqa: E221
                )

        return entities

    def create_report_from_member_content_with_references(
        self, content: Dict
    ) -> Tuple[Dict, List[Dict]]:
        """
        Create a STIX Report object from a member content using the references endpoint to get all entities.

        Args:
            content: The member content dictionary

        Returns:
            Tuple containing:
                - The STIX Report object dictionary
                - List of related STIX objects (indicators, observables, etc.)
        """
        if self.logger:
            self.logger.debug(
                f"Creating report from member content with ID: {content.get('id')}"
            )

        title = content.get("title", "Untitled Report")
        description = content.get("description", "")
        summary = content.get("summary", "")
        published_on = content.get("published_on", content.get("published_date"))
        modified = content.get("updated_date", content.get("updated_on"))
        content_id = content.get("id")
        slug = content.get("slug", "")
        tlp = content.get("tlp", TLPLevel.CLEAR.value)
        self.converter = self.get_stix_converter(tlp)

        if published_on:
            published = published_on
            try:
                datetime.fromisoformat(published_on.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        else:
            published = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        content_tlp = self.converter.tlp_map.get(tlp, "tlp:white")
        content_marking = self.converter._create_tlp_marking(content_tlp)

        labels = []
        if content.get("category"):
            labels.append(content["category"])
        if content.get("sub_category") and content["sub_category"].get("name"):
            labels.append(content["sub_category"]["name"])

        report_id = (
            f"report--{str(uuid.uuid5(uuid.NAMESPACE_URL, f'catalyst-{content_id}'))}"
        )

        related_objects = []

        entity_mappings = {
            "threat-actor": [],
            "intrusion-set": [],
            "malware": [],
            "tool": [],
            "vulnerability": [],
            "campaign": [],
            "indicator": [],
            "identity": [],
            "location": [],
        }

        custom_properties = {
            "x_opencti_report_status": 2,
            "x_opencti_create_indicator": True,
            "x_catalyst_content_id": content_id,
            "x_catalyst_updated_on": content.get("updated_on"),
            "x_catalyst_source": "PRODAFT CATALYST",
            "x_catalyst_member_content_id": content_id if content_id else None,
        }

        if "metadata" in content and isinstance(content["metadata"], dict):
            for key, value in content["metadata"].items():
                custom_prop_name = (
                    f"x_catalyst_{key.replace('-', '_').replace(' ', '_')}"
                )
                custom_properties[custom_prop_name] = value

        if "tags" in content and isinstance(content["tags"], list):
            custom_properties["x_catalyst_tags"] = content["tags"]

        if content_id:
            try:
                all_entities = self.extract_entities_from_member_content(content_id)

                collected_object_refs = [content_marking.id]

                # Create the external reference for the report
                external_reference = self.converter._create_external_reference(
                    source_name=self.converter.author_name,
                    external_id=content_id,
                    is_report=True,
                )

                # Process observables
                for observable in all_entities.get("observable", []):
                    entity_id = observable.get("id")
                    entity_value = observable.get("value")
                    entity_type = observable.get("type")

                    if entity_id and entity_value and entity_type:
                        observable_data = {
                            "id": entity_id,
                            "value": entity_value,
                            "type": entity_type,
                            "post_id": content_id,
                        }

                        observable_data["tlp_marking"] = content_marking

                        (
                            indicator,
                            relationships,
                            observable_obj,
                        ) = self.converter.convert_observable_to_stix(
                            observable_data,
                            report_reference=external_reference,
                            report_id=report_id,
                        )

                        if indicator:
                            # Add the indicator to the report
                            related_objects.append(indicator)
                            collected_object_refs.append(indicator.id)
                            entity_mappings["indicator"].append(indicator.id)

                        # Add the observable to the report if it exists
                        if observable_obj:
                            related_objects.append(observable_obj)
                            collected_object_refs.append(observable_obj.id)
                            if self.logger:
                                self.logger.debug(
                                    f"Added observable: {entity_value} ({entity_type})"
                                )

                        # Add the relationships to related objects if they exist
                        for relationship in relationships:
                            related_objects.append(relationship)
                            collected_object_refs.append(relationship.id)
                            if self.logger:
                                self.logger.debug(
                                    f"Added relationship for observable {entity_value}"
                                )

                        if self.logger:
                            self.logger.debug(
                                f"Added indicator: {entity_value} ({entity_type})"
                            )

                # Process threat actors
                for threat_actor in all_entities.get(
                    "threatactor", []
                ) + all_entities.get("threat_actor", []):
                    entity_id = threat_actor.get("id")
                    entity_value = threat_actor.get("value")
                    context = threat_actor.get("context")

                    if entity_id and entity_value:
                        try:
                            # Fetch detailed information for the threat actor
                            detailed_threat_actor = self._get_threat_actor_details(
                                entity_id
                            )

                            if self.logger:
                                self.logger.debug(
                                    f"Retrieved detailed information for threat actor: {entity_value}"
                                )

                            ta_object = self.converter.create_detailed_threat_actor(
                                detailed_threat_actor,
                                context,
                                report_reference=external_reference,
                            )

                            # Process relationships from detailed threat actor data regardless of type
                            """
                            # 1. Process attack patterns
                            attack_pattern_data = detailed_threat_actor.get("attack_patterns", [])
                            if isinstance(attack_pattern_data, list):
                                for attack_pattern in attack_pattern_data:
                                    pattern_id = attack_pattern.get("id")
                                    pattern_name = attack_pattern.get("name")

                                    if pattern_id and pattern_name:
                                        # Create the attack pattern
                                        attack_pattern_obj = self.converter.create_attack_pattern(
                                            pattern_id,
                                            pattern_name,
                                            attack_pattern.get("description"),
                                            report_reference=external_reference,
                                        )
                                        related_objects.append(attack_pattern_obj)
                                        collected_object_refs.append(attack_pattern_obj.id)

                                        # Create relationship
                                        rel = self._create_relationship_objects(
                                            ta_object.id,
                                            attack_pattern_obj.id,
                                            "uses",
                                            external_reference
                                        )
                                        related_objects.append(rel)
                                        collected_object_refs.append(rel.id)

                                        if self.logger:
                                            self.logger.debug(f"Added attack pattern {pattern_name} used by {entity_value}")

                            # 2. Process campaigns
                            campaign_data = detailed_threat_actor.get("campaigns", [])
                            if isinstance(campaign_data, list):
                                for campaign in campaign_data:
                                    campaign_id = campaign.get("id")
                                    campaign_name = campaign.get("name")

                                    if campaign_id and campaign_name:
                                        # Create the campaign
                                        campaign_obj = self.converter.create_campaign(
                                            campaign_id,
                                            campaign_name,
                                            campaign.get("description"),
                                            report_reference=external_reference,
                                        )
                                        related_objects.append(campaign_obj)
                                        collected_object_refs.append(campaign_obj.id)

                                        # Create relationship with appropriate relationship type
                                        rel = self._create_relationship_objects(
                                            ta_object.id,
                                            campaign_obj.id,
                                            "attributed-to",
                                            external_reference
                                        )
                                        related_objects.append(rel)
                                        collected_object_refs.append(rel.id)

                                        if self.logger:
                                            self.logger.debug(f"Added campaign {campaign_name} attributed to {entity_value}")

                            # 3. Process countries/suspected origins
                            origin_data = detailed_threat_actor.get("suspected_origins", [])
                            if isinstance(origin_data, list):
                                for country in origin_data:
                                    country_id = country.get("id")
                                    country_name = country.get("name")

                                    if country_id and country_name:
                                        # Create the location
                                        location_obj = self.converter.create_country_location(
                                            country_id,
                                            country_name,
                                            None,
                                            report_reference=external_reference,
                                        )
                                        related_objects.append(location_obj)
                                        collected_object_refs.append(location_obj.id)

                                        # Create relationship
                                        rel = self._create_relationship_objects(
                                            ta_object.id,
                                            location_obj.id,
                                            "originates-from",
                                            external_reference
                                        )
                                        related_objects.append(rel)
                                        collected_object_refs.append(rel.id)

                                        if self.logger:
                                            self.logger.debug(f"Added suspected origin {country_name} for {entity_value}")
                            """
                            is_abstract = detailed_threat_actor.get(
                                "is_abstract", False
                            )

                            related_objects.append(ta_object)
                            collected_object_refs.append(ta_object.id)

                            if is_abstract:
                                if "intrusion-set" not in entity_mappings:
                                    entity_mappings["intrusion-set"] = []
                                entity_mappings["intrusion-set"].append(ta_object.id)
                                if self.logger:
                                    self.logger.debug(
                                        f"Added intrusion set: {entity_value}"
                                    )
                            else:
                                entity_mappings["threat-actor"].append(ta_object.id)
                                if self.logger:
                                    self.logger.debug(
                                        f"Added threat actor: {entity_value}"
                                    )
                        except Exception as e:
                            if self.logger:
                                self.logger.warning(
                                    f"Failed to fetch detailed threat actor info for {entity_id}: {str(e)}"
                                )
                            # Fall back to basic threat actor creation
                            ta_object = self.converter.create_threat_actor(
                                entity_id,
                                entity_value,
                                context,
                                report_reference=external_reference,
                            )

                        related_objects.append(ta_object)
                        collected_object_refs.append(ta_object.id)
                        entity_mappings["threat-actor"].append(ta_object.id)

                        if self.logger:
                            self.logger.debug(f"Added threat actor: {entity_value}")

                # Process malware
                for malware in all_entities.get("malware", []):
                    entity_id = malware.get("id")
                    entity_value = malware.get("value")
                    context = malware.get("context")

                    if entity_id and entity_value:
                        malware_object = self.converter.create_malware(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(malware_object)
                        collected_object_refs.append(malware_object.id)
                        entity_mappings["malware"].append(malware_object.id)

                        if self.logger:
                            self.logger.debug(f"Added malware: {entity_value}")

                # Process tools
                for tool in all_entities.get("tool", []):
                    entity_id = tool.get("id")
                    entity_value = tool.get("value")
                    context = tool.get("context")

                    if entity_id and entity_value:
                        tool_object = self.converter.create_tool(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(tool_object)
                        collected_object_refs.append(tool_object.id)
                        entity_mappings["tool"].append(tool_object.id)

                        if self.logger:
                            self.logger.debug(f"Added tool: {entity_value}")

                # Process vulnerabilities
                for vuln in all_entities.get("vulnerability", []):
                    entity_id = vuln.get("id")
                    entity_value = vuln.get("value")
                    context = vuln.get("context")

                    if entity_id and entity_value:
                        vuln_object = self.converter.create_vulnerability(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(vuln_object)
                        collected_object_refs.append(vuln_object.id)
                        entity_mappings["vulnerability"].append(vuln_object.id)

                        if self.logger:
                            self.logger.debug(f"Added vulnerability: {entity_value}")

                # Process campaigns
                for campaign in all_entities.get("campaign", []):
                    entity_id = campaign.get("id")
                    entity_value = campaign.get("value")
                    context = campaign.get("context")

                    if entity_id and entity_value:
                        campaign_object = self.converter.create_campaign(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(campaign_object)
                        collected_object_refs.append(campaign_object.id)
                        entity_mappings["campaign"].append(campaign_object.id)

                        if self.logger:
                            self.logger.debug(f"Added campaign: {entity_value}")

                # Process organizations
                for org in all_entities.get("organization", []):
                    entity_id = org.get("id")
                    entity_value = org.get("value")
                    context = org.get("context")

                    if entity_id and entity_value:
                        identity = self.converter.create_organization_identity(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(identity)
                        collected_object_refs.append(identity.id)
                        entity_mappings["identity"].append(identity.id)

                        if self.logger:
                            self.logger.debug(
                                f"Added organization identity: {entity_value}"
                            )

                # Process industries
                for industry in all_entities.get("industry", []):
                    entity_id = industry.get("id")
                    entity_value = industry.get("value")
                    context = industry.get("context")

                    if entity_id and entity_value:
                        identity = self.converter.create_industry_identity(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(identity)
                        collected_object_refs.append(identity.id)
                        entity_mappings["identity"].append(identity.id)

                        if self.logger:
                            self.logger.debug(
                                f"Added industry identity: {entity_value}"
                            )

                # Process sectors
                for sector in all_entities.get("sector", []):
                    entity_id = sector.get("id")
                    entity_value = sector.get("value")
                    context = sector.get("context")

                    if entity_id and entity_value:
                        identity = self.converter.create_sector_identity(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(identity)
                        collected_object_refs.append(identity.id)
                        entity_mappings["identity"].append(identity.id)

                        if self.logger:
                            self.logger.debug(f"Added sector identity: {entity_value}")

                # Process countries
                for country in all_entities.get("country", []):
                    entity_id = country.get("id")
                    entity_value = country.get("value")
                    context = country.get("context")

                    if entity_id and entity_value:
                        location = self.converter.create_country_location(
                            entity_id,
                            entity_value,
                            context,
                            report_reference=external_reference,
                        )
                        related_objects.append(location)
                        collected_object_refs.append(location.id)
                        entity_mappings["location"].append(location.id)

                        if self.logger:
                            self.logger.debug(f"Added country location: {entity_value}")

                # TTP relationship processing - REMOVED
                # self._process_ttp_entities(
                #    all_entities,
                #    related_objects,
                #    collected_object_refs,
                #    entity_mappings,
                #    external_reference
                # )
                detailed_content = (
                    self.get_member_content(content_id)
                    if self.catalyst_authenticated
                    else self.get_member_content(slug)
                )
                content = detailed_content.get("content", "")
                report = self.converter.create_report(
                    content_id=content_id,
                    title=title,
                    description=content or summary or description,
                    published=published,
                    modified=modified,
                    object_refs=collected_object_refs,
                    object_marking_refs=[content_marking.id],
                    labels=labels if labels else None,
                    custom_properties=custom_properties,
                )

                if self.logger:
                    self.logger.info(
                        f"Created report with {len(related_objects)} related objects"
                    )

            except Exception as e:
                if self.logger:
                    self.logger.error(
                        f"Error creating report from content {content_id}: {str(e)}"
                    )
                raise
        else:
            if self.logger:
                self.logger.error(f"Error creating report from content {content_id}")

        if self.logger:
            self.logger.debug(
                f"Completed creation of report {report.id} with {len(report.object_refs)} referenced objects"
            )

        return report, related_objects

    def create_report_from_member_content(
        self, content: Dict
    ) -> Tuple[Dict, List[Dict]]:
        """
        Create a STIX Report object from a member content.

        Args:
            content: The member content dictionary

        Returns:
            Tuple containing:
                - The STIX Report object dictionary
                - List of related STIX objects (indicators, observables, etc.)
        """
        if self.logger:
            self.logger.debug(
                "Using reference-based entity extraction for better report creation"
            )
        return self.create_report_from_member_content_with_references(content)

    def get_stix_converter(self, tlp: TLPLevel):
        """
        Get or create a StixConverter instance.

        Returns:
            StixConverter: A configured StixConverter instance
        """
        from .stix_converter import StixConverter

        return StixConverter(
            author_name="PRODAFT CATALYST",
            tlp_level=tlp,
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
        )

    def _create_relationship_objects(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str = "related-to",
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Relationship:
        """
        Create a STIX relationship object between two entities.

        Args:
            source_id: ID of the source object
            target_id: ID of the target object
            relationship_type: Type of relationship (e.g., 'uses', 'indicates')
            report_reference: Optional reference to the report this relationship is from

        Returns:
            STIX relationship object
        """
        return self.converter.create_relationship(
            source_ref=source_id,
            target_ref=target_id,
            relationship_type=relationship_type,
            report_reference=report_reference,
        )

    def get_post_references(
        self, post_id: str, entity_type: str = None, page: int = 1, page_size: int = 100
    ) -> Dict:
        """
        Get references (entities) associated with a post.

        Args:
            post_id: The ID of the post
            entity_type: Optional filter for entity type (e.g., 'observable', 'threat-actor')
            page: Page number for paginated results
            page_size: Number of results per page

        Returns:
            Response data containing the references
        """
        params = {"post": post_id, "page": page, "page_size": page_size}

        if entity_type:
            params["entity_type"] = entity_type

        if self.logger:
            self.logger.debug(
                f"Getting post references for post {post_id}, entity_type={entity_type}"
            )

        return self._handle_request("GET", "/posts/references/", params=params)

    def _get_all_references_for_post(self, post_id: str) -> List[Dict]:
        """
        Get all references for a specific post, handling pagination.

        Args:
            post_id: ID of the post to get references for

        Returns:
            List of all reference objects
        """
        if self.logger:
            self.logger.debug(f"Fetching all references for post {post_id}")

        all_references = []
        page = 1
        more_pages = True

        try:
            while more_pages:
                references = self.get_post_references(
                    post_id, entity_type=None, page=page
                )

                if references and "results" in references and references["results"]:
                    all_references.extend(references["results"])

                    if self.logger:
                        self.logger.debug(
                            f"Retrieved {len(references['results'])} references from page {page}"
                        )

                    if references.get("next"):
                        page += 1
                        if self.logger:
                            self.logger.debug(
                                f"Fetching next page ({page}) of references"
                            )
                    else:
                        more_pages = False
                else:
                    more_pages = False

        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Error fetching references for post {post_id}: {str(e)}"
                )

        if self.logger:
            self.logger.info(
                f"Retrieved {len(all_references)} total references for post {post_id}"
            )

        return all_references

    def _process_ttp_entities(
        self,
        all_entities: Dict,
        related_objects: List,
        collected_object_refs: List,
        entity_mappings: Dict,
        external_reference: stix2.ExternalReference = None,
    ) -> None:
        """
        Process TTPs (Tactics, Techniques, and Procedures) from CATALYST data. This function is currently not used.

        It is preserved here for documentation purposes, to make it easy to re-enable
        if needed in the future.

        Args:
            all_entities: Dictionary containing all entities by type
            related_objects: List to add the created objects to
            collected_object_refs: List to add object refs to for the report
            entity_mappings: Dictionary mapping entity types to lists of entity IDs
            external_reference: Optional reference to the report
        """
        # Process attack patterns
        for attack_pattern in all_entities.get("attackpattern", []):
            entity_id = attack_pattern.get("id")
            entity_value = attack_pattern.get("value")
            context = attack_pattern.get("context")

            if entity_id and entity_value:
                attack_pattern_object = self.converter.create_attack_pattern(
                    entity_id,
                    entity_value,
                    context,
                    report_reference=external_reference,
                )
                related_objects.append(attack_pattern_object)
                collected_object_refs.append(attack_pattern_object.id)
                entity_mappings["attack-pattern"].append(attack_pattern_object.id)

                if self.logger:
                    self.logger.debug(f"Added attack pattern: {entity_value}")

        # Create TTP relationships

        # Threat Actor uses Attack Pattern
        for ta_id in entity_mappings["threat-actor"]:
            for attack_pattern_id in entity_mappings["attack-pattern"]:
                rel = self._create_relationship_objects(
                    ta_id, attack_pattern_id, "uses", external_reference
                )
                related_objects.append(rel)
                collected_object_refs.append(rel.id)

        # Intrusion Set uses Attack Pattern
        for is_id in entity_mappings["intrusion-set"]:
            for attack_pattern_id in entity_mappings["attack-pattern"]:
                rel = self._create_relationship_objects(
                    is_id, attack_pattern_id, "uses", external_reference
                )
                related_objects.append(rel)
                collected_object_refs.append(rel.id)

        # Malware uses Attack Pattern
        for malware_id in entity_mappings["malware"]:
            for attack_pattern_id in entity_mappings["attack-pattern"]:
                rel = self._create_relationship_objects(
                    malware_id, attack_pattern_id, "uses", external_reference
                )
                related_objects.append(rel)
                collected_object_refs.append(rel.id)

    def _get_threat_actor_details(self, threat_actor_id: str) -> Dict:
        """
        Get details for a specific threat actor.

        Args:
            threat_actor_id: ID of the threat actor

        Returns:
            Dictionary containing detailed information about the threat actor:
            - id: The unique identifier for the threat actor
            - name: The name of the threat actor
            - description: Detailed description
            - is_group: Boolean indicating if this is a group (true) or individual (false)
            - aliases: List of alternative names
            - motivation: The primary motivation of the threat actor
            - suspected_origins: List of countries of suspected origin
            - attack_patterns: List of attack patterns used by the threat actor
            - campaigns: List of campaigns attributed to the threat actor
        """
        if self.logger:
            self.logger.debug(
                f"Fetching detailed information for threat actor ID: {threat_actor_id}"
            )

        return self._handle_request("GET", f"/actors/{threat_actor_id}/")
