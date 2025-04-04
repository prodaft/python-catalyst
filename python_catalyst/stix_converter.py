"""STIX converter for CATALYST data."""

import ipaddress
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import stix2
from pycti import (
    AttackPattern,
    Campaign,
    CustomObservableCryptocurrencyWallet,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    MarkingDefinition,
    Report,
    StixCoreRelationship,
    ThreatActor,
    Tool,
    Vulnerability,
)

from .enums import ObservableType, TLPLevel


class StixConverter:
    """Converts CATALYST data to STIX 2.1 format."""

    def __init__(
        self,
        author_name: str = "CATALYST",
        tlp_level: str = "tlp:white",
        create_observables: bool = True,
        create_indicators: bool = True,
    ):
        """
        Initialize the STIX converter.

        Args:
            author_name: Name of the identity that will be the author of STIX objects
            tlp_level: TLP level for marking definitions ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')
        """
        self.author_name = author_name
        self.tlp_level = tlp_level.lower()

        # Create author identity
        self.identity = self._create_identity()

        # Create TLP
        self.tlp_marking = self._create_tlp_marking()

        self.observable_type_map = {
            ObservableType.BTC_ADDRESS.value: self._create_cryptocurrency_wallet_observable,
            ObservableType.URL.value: self._create_url_observable,
            ObservableType.DOMAIN_NAME.value: self._create_domain_observable,
            ObservableType.IP_ADDRESS.value: self._create_ip_observable,
            ObservableType.FILE_HASH_MD5.value: lambda value, report_reference=None: self._create_file_observable(
                value, "MD5", report_reference
            ),
            ObservableType.FILE_HASH_SHA1.value: lambda value, report_reference=None: self._create_file_observable(
                value, "SHA-1", report_reference
            ),
            ObservableType.FILE_HASH_SHA256.value: lambda value, report_reference=None: self._create_file_observable(
                value, "SHA-256", report_reference
            ),
            ObservableType.EMAIL.value: self._create_email_observable,
            ObservableType.JABBER_ADDRESS.value: self._create_user_account_observable,
            ObservableType.TOX_ADDRESS.value: self._create_user_account_observable,
            ObservableType.TELEGRAM.value: self._create_user_account_observable,
            ObservableType.X.value: self._create_user_account_observable,
        }

        self.tlp_map = {
            TLPLevel.CLEAR.value: "tlp:clear",
            TLPLevel.GREEN.value: "tlp:green",
            TLPLevel.AMBER.value: "tlp:amber",
            TLPLevel.RED.value: "tlp:red",
            TLPLevel.AMBER_STRICT.value: "tlp:amber+strict",
        }

        self._external_ref_cache = {}
        self._post_ref_cache = {}
        self._entity_cache = {}

        self.create_observables = create_observables
        self.create_indicators = create_indicators

    def _create_identity(self) -> Identity:
        """
        Create an identity for the author of STIX objects.

        Returns:
            STIX Identity object
        """
        return stix2.Identity(
            id=Identity.generate_id(
                name=self.author_name, identity_class="organization"
            ),
            name=self.author_name,
            identity_class="organization",
            description=f"Data from {self.author_name} platform",
        )

    def _create_tlp_marking(self, tlp_level: str = None) -> stix2.MarkingDefinition:
        """
        Create a TLP marking definition based on the specified TLP level.

        Args:
            tlp_level: TLP level ('white', 'green', 'amber', 'red')
                      If None, uses the instance default

        Returns:
            STIX MarkingDefinition object
        """
        level = tlp_level.lower() if tlp_level else self.tlp_level

        tlp_map = {
            "tlp:white": stix2.TLP_WHITE,
            "tlp:clear": stix2.TLP_WHITE,
            "tlp:green": stix2.TLP_GREEN,
            "tlp:amber": stix2.TLP_AMBER,
            "tlp:amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "tlp:red": stix2.TLP_RED,
        }

        return tlp_map.get(level, stix2.TLP_WHITE)

    def _create_external_reference(
        self, source_name: str, external_id: str, is_report: bool = False
    ) -> stix2.ExternalReference:
        """
        Create an external reference to the CATALYST platform. Uses caching to avoid duplicate external references for the same source and ID.

        Args:
            source_name: Name of the source
            external_id: ID in the external source

        Returns:
            STIX ExternalReference object
        """
        cache_key = f"{source_name}:{external_id}"  # noqa: E231

        if cache_key in self._external_ref_cache:
            return self._external_ref_cache[cache_key]

        if source_name == "PRODAFT CATALYST" and "--" not in external_id and is_report:
            ext_ref = stix2.ExternalReference(
                source_name=source_name,
                external_id=external_id,
                url=f"https://catalyst.prodaft.com/report/{external_id}/",  # noqa: E231
            )
        else:
            ext_ref = stix2.ExternalReference(
                source_name=source_name,
                external_id=external_id,
            )

        self._external_ref_cache[cache_key] = ext_ref

        return ext_ref

    def get_post_reference(self, post_id: str) -> str:
        """
        Get a cached STIX ID for a post reference. Creates and caches it if it doesn't exist.

        Args:
            post_id: The ID of the post

        Returns:
            STIX ID for the post (report--UUID)
        """
        if post_id in self._post_ref_cache:
            return self._post_ref_cache[post_id]

        post_stix_id = f"report--{uuid.uuid5(uuid.NAMESPACE_URL, post_id)}"
        self._post_ref_cache[post_id] = post_stix_id

        return post_stix_id

    def create_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Relationship:
        """
        Create a STIX relationship between two objects.

        Args:
            source_ref: Source object ID
            target_ref: Target object ID
            relationship_type: Type of relationship (e.g., 'uses', 'indicates', 'targets', 'based-on')
            report_reference: Optional reference to the report this relationship is from

        Returns:
            STIX Relationship object
        """
        cache_key = (
            f"relationship:{relationship_type}:{source_ref}:{target_ref}"  # noqa: E231
        )
        if cache_key in self._entity_cache:
            rel_id = self._entity_cache[cache_key]
            return stix2.Relationship(
                id=rel_id,
                source_ref=source_ref,
                target_ref=target_ref,
                relationship_type=relationship_type,
            )

        created_by_ref = self.get_created_by_ref()

        external_references = []
        if report_reference:
            external_references = [report_reference]

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        self._entity_cache[cache_key] = relationship.id

        return relationship

    def _create_ip_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> Union[stix2.IPv4Address, stix2.IPv6Address]:
        """
        Create an IP address observable.

        Args:
            value: IP address value
            report_reference: Optional reference to the report this observable is from

        Returns:
            IPv4Address or IPv6Address STIX object
        """
        try:
            ip = ipaddress.ip_address(value)
            created_by_ref = self.get_created_by_ref()

            custom_properties = {"x_opencti_created_by_ref": created_by_ref}
            if report_reference:
                custom_properties["x_opencti_external_references"] = [report_reference]

            if ip.version == 4:
                return stix2.IPv4Address(
                    value=value,
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties=custom_properties,
                )
            else:
                return stix2.IPv6Address(
                    value=value,
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties=custom_properties,
                )
        except ValueError:
            raise ValueError(f"Invalid IP address: {value}")

    def _create_domain_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> stix2.DomainName:
        """
        Create a domain name observable.

        Args:
            value: Domain name value
            report_reference: Optional reference to the report this observable is from

        Returns:
            DomainName STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        return stix2.DomainName(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_url_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> stix2.URL:
        """
        Create a URL observable.

        Args:
            value: URL value
            report_reference: Optional reference to the report this observable is from

        Returns:
            URL STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        return stix2.URL(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_email_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> stix2.EmailAddress:
        """
        Create an email address observable.

        Args:
            value: Email address value
            report_reference: Optional reference to the report this observable is from

        Returns:
            EmailAddress STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        return stix2.EmailAddress(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_file_observable(
        self,
        value: str,
        hash_type: str,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.File:
        """
        Create a file observable with hash.

        Args:
            value: Hash value
            hash_type: Type of hash (MD5, SHA-1, SHA-256)
            report_reference: Optional reference to the report this observable is from

        Returns:
            File STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        hashes = {hash_type: value}
        return stix2.File(
            hashes=hashes,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_user_account_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> stix2.UserAccount:
        """
        Create a user account observable.

        Args:
            value: User account value
            report_reference: Optional reference to the report this observable is from

        Returns:
            UserAccount STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]
        return stix2.UserAccount(
            user_id=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_cryptocurrency_wallet_observable(
        self, value: str, report_reference: stix2.ExternalReference = None
    ) -> stix2.CustomObservable:
        """
        Create a cryptocurrency wallet observable.

        Args:
            value: Wallet address
            report_reference: Optional reference to the report this observable is from

        Returns:
            CustomObservable STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        return CustomObservableCryptocurrencyWallet(
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_custom_observable(
        self,
        value: str,
        observable_type: str,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.CustomObservable:
        """
        Create a custom observable for types not directly supported by STIX.

        Args:
            value: Observable value
            observable_type: Type of observable
            report_reference: Optional reference to the report this observable is from

        Returns:
            CustomObservable STIX object
        """
        created_by_ref = self.get_created_by_ref()

        custom_properties = {"x_opencti_created_by_ref": created_by_ref}
        if report_reference:
            custom_properties["x_opencti_external_references"] = [report_reference]

        return stix2.CustomObservable(
            id=f"x-{observable_type.lower()}--{str(uuid.uuid4())}",
            type=f"x-{observable_type.lower()}",
            value=value,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def _create_observable_from_data(self, observable: Dict) -> Optional[Any]:
        """
        Create a STIX observable object from CATALYST observable data.

        Args:
            observable: CATALYST observable data

        Returns:
            STIX Observable object or None if can't be created
        """
        observable_type = observable.get("type")
        value = observable.get("value", "")
        report_reference = observable.get("report_reference")

        if not observable_type or not value:
            return None

        # Find the appropriate factory method for this observable type
        factory_method = self.observable_type_map.get(observable_type)

        if factory_method:
            return factory_method(value, report_reference)

        # If no specific factory method, try to create a custom observable
        return self._create_custom_observable(value, observable_type, report_reference)

    def _create_based_on_relationship(
        self, indicator: stix2.Indicator, observable: Any
    ) -> stix2.Relationship:
        """
        Create a 'based-on' relationship between an indicator and its observable.

        Args:
            indicator: STIX Indicator object
            observable: STIX Observable object

        Returns:
            STIX Relationship object
        """
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on", indicator.id, observable.id
            ),
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            created_by_ref=self.get_created_by_ref(),
            object_marking_refs=[self.tlp_marking.id],
        )

    def create_organization_identity(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Identity:
        """
        Create a STIX Identity object for an organization from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Organization name
            context: Optional context/description for the organization
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Identity object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Organization {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()
        identity = stix2.Identity(
            id=Identity.generate_id(entity_value, "organization"),
            name=entity_value,
            description=description,
            identity_class="organization",
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return identity

    def create_industry_identity(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Identity:
        """
        Create a STIX Identity object for an industry from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Industry name
            context: Optional context/description for the industry
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Identity object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Industry {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        identity = stix2.Identity(
            id=Identity.generate_id(entity_value, "class"),
            name=entity_value,
            description=description,
            identity_class="class",
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return identity

    def create_sector_identity(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Identity:
        """
        Create a STIX Identity object for a sector from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Sector name
            context: Optional context/description for the sector
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Identity object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Sector {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        identity = stix2.Identity(
            id=Identity.generate_id(entity_value, "class"),
            name=entity_value,
            description=description,
            identity_class="class",
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return identity

    def create_country_location(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Location:
        """
        Create a STIX Location object for a country from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Country name
            context: Optional context/description for the country
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Location object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Country {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        location = stix2.Location(
            id=Location.generate_id(entity_value, x_opencti_location_type="country"),
            name=entity_value,
            description=description,
            country=entity_value,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return location

    def create_threat_actor(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
        actor_type: str = "threat-actor-group",
    ) -> stix2.ThreatActor:
        """
        Create a STIX Threat Actor object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Threat Actor name
            context: Optional context/description for the threat actor
            report_reference: Optional reference to the report this entity is from
            actor_type: Type of threat actor ("threat-actor-group" or "threat-actor-individual")

        Returns:
            STIX Threat Actor object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Threat Actor {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        threat_actor = stix2.ThreatActor(
            id=ThreatActor.generate_id(entity_value, actor_type),
            name=entity_value,
            description=description,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
            custom_properties={"x_catalyst_threat_actor_id": entity_id},
        )

        return threat_actor

    def create_malware(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Malware:
        """
        Create a STIX Malware object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Malware name
            context: Optional context/description for the malware
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Malware object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Malware {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        malware = stix2.Malware(
            id=Malware.generate_id(entity_value),
            name=entity_value,
            description=description,
            is_family=False,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return malware

    def create_tool(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Tool:
        """
        Create a STIX Tool object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Tool name
            context: Optional context/description for the tool
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Tool object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Tool {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        tool = stix2.Tool(
            id=Tool.generate_id(entity_value),
            name=entity_value,
            description=description,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return tool

    def create_vulnerability(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Vulnerability:
        """
        Create a STIX Vulnerability object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Vulnerability name
            context: Optional context/description for the vulnerability
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Vulnerability object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Vulnerability {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(entity_value),
            name=entity_value,
            description=description,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return vulnerability

    def create_attack_pattern(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.AttackPattern:
        """
        Create a STIX Attack Pattern object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Attack Pattern name
            context: Optional context/description for the attack pattern
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Attack Pattern object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Attack Pattern {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(entity_value),
            name=entity_value,
            description=description,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return attack_pattern

    def create_campaign(
        self,
        entity_id: str,
        entity_value: str,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Campaign:
        """
        Create a STIX Campaign object from CATALYST entity data.

        Args:
            entity_id: CATALYST entity ID
            entity_value: Campaign name
            context: Optional context/description for the campaign
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX Campaign object
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        description = f"Campaign {entity_value} from CATALYST"
        if context:
            description = f"{context}"

        created_by_ref = self.get_created_by_ref()

        campaign = stix2.Campaign(
            id=Campaign.generate_id(entity_value),
            name=entity_value,
            description=description,
            created_by_ref=created_by_ref,
            object_marking_refs=[self.tlp_marking.id],
            external_references=external_references if external_references else None,
        )

        return campaign

    def convert_observable_to_stix(
        self,
        observable_data: Dict,
        report_reference: stix2.ExternalReference = None,
        report_id: str = None,
    ) -> Tuple[Any, List[Optional[stix2.Relationship]], Optional[Any]]:
        """
        Convert an observable dictionary to a STIX Cyber Observable object and an Indicator.

        Args:
            observable_data: Dictionary containing observable data (type and value)
                            May also include 'post_id' to link to a post
                            May include 'tlp_marking' for custom TLP level
            report_reference: Optional reference to the report this observable is from
            report_id: Optional STIX ID of the report to create a relationship with

        Returns:
            Tuple containing:
                - STIX Indicator object or None if conversion fails
                - List of relationships created (post relationship and/or report relationship)
                - STIX Observable object or None if creation fails
        """
        try:
            observable_type = observable_data.get("type")
            value = observable_data.get("value")

            if not observable_type or not value:
                return None, [], None

            tlp_marking = observable_data.get("tlp_marking")
            if self.create_indicators:
                indicator = self.create_indicator_from_observable(
                    observable_data, tlp_marking, report_reference
                )
            else:
                indicator = None

            if self.create_observables:
                observable_data_with_ref = observable_data.copy()
                observable_data_with_ref["report_reference"] = report_reference
                observable = self._create_observable_from_data(observable_data_with_ref)
            else:
                observable = None

            if not observable and indicator:
                return indicator, [], None

            if not indicator and observable:
                return None, [], observable

            if indicator and observable:
                based_on = self._create_based_on_relationship(indicator, observable)

            relationships = [based_on]

            return indicator, relationships, observable

        except Exception as e:
            observable_type = observable_data.get("type", "unknown")
            value = observable_data.get("value", "unknown")
            print(
                f"Error creating STIX observable/indicator for {observable_type}:{value}: {str(e)}"  # noqa: E231
            )
            return None, [], None

    def create_indicator_from_observable(
        self,
        observable_data: Union[Dict, Any],
        tlp_marking=None,
        report_reference: stix2.ExternalReference = None,
    ) -> stix2.Indicator:
        """
        Create a STIX Indicator object from an observable.

        Args:
            observable_data: Dictionary containing observable data with keys 'id', 'value', and 'type'
                            or a STIX Cyber Observable object
            tlp_marking: Optional custom TLP marking to use instead of the default
            report_reference: Optional reference to the report this indicator is from

        Returns:
            STIX Indicator object or None if creation fails
        """
        if isinstance(observable_data, dict):
            observable_type = observable_data.get("type")
            value = observable_data.get("value")
            # entity_id = observable_data.get("id")
        else:
            try:
                if hasattr(observable_data, "type") and hasattr(observable_data, "id"):
                    observable_type = observable_data.type
                    # entity_id = observable_data.id

                    if observable_type in [
                        "ipv4-addr",
                        "ipv6-addr",
                        "domain-name",
                        "url",
                        "email-addr",
                    ]:
                        value = observable_data.value
                    elif observable_type == "file":
                        if (
                            hasattr(observable_data, "hashes")
                            and observable_data.hashes
                        ):
                            for hash_type, hash_value in observable_data.hashes.items():
                                value = hash_value
                                observable_type = (
                                    f"file:hashes:'{hash_type}'"  # noqa: E231
                                )
                                break
                        else:
                            value = None
                    elif observable_type == "user-account":
                        value = observable_data.user_id
                        observable_type = (
                            f"user-account:{observable_data.account_type}"  # noqa: E231
                            if hasattr(observable_data, "account_type")
                            else "user-account"
                        )
                    else:
                        value = getattr(observable_data, "value", None)
                else:
                    return None
            except Exception:
                return None

        if not observable_type or not value:
            return None

        pattern = ""
        if observable_type == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{value}']"
        elif observable_type == "ipv6-addr":
            pattern = f"[ipv6-addr:value = '{value}']"
        elif observable_type == "domain-name":
            pattern = f"[domain-name:value = '{value}']"
        elif observable_type == "url":
            pattern = f"[url:value = '{value}']"
        elif observable_type == "email-addr":
            pattern = f"[email-addr:value = '{value}']"
        elif observable_type == ObservableType.FILE_HASH_MD5.value:
            pattern = f"[file:hashes.'MD5' = '{value}']"
        elif observable_type == ObservableType.FILE_HASH_SHA1.value:
            pattern = f"[file:hashes.'SHA-1' = '{value}']"
        elif observable_type == ObservableType.FILE_HASH_SHA256.value:
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        elif observable_type.startswith("file:hashes"):
            hash_type = observable_type.split(":")[2].strip("'")
            pattern = f"[file:hashes.'{hash_type}' = '{value}']"
        elif observable_type in [
            ObservableType.JABBER_ADDRESS.value,
            ObservableType.TOX_ADDRESS.value,
            ObservableType.TELEGRAM.value,
            ObservableType.X.value,
        ] or observable_type.startswith("user-account"):
            account_type = observable_type.lower()
            if ":" in account_type:
                account_type = account_type.split(":")[1]
            pattern = f"[user-account:account_type = '{account_type}' AND user-account:user_id = '{value}']"  # noqa: E231
        elif observable_type == ObservableType.BTC_ADDRESS.value:
            pattern = f"[cryptocurrency-wallet:value = '{value}']"
        else:
            pattern = f"[x-{observable_type.lower()}:value = '{value}']"  # noqa: E231

        external_references = []
        if report_reference:
            external_references = [report_reference]

        indicator_id = Indicator.generate_id(pattern)

        indicator_name = f"{value}"

        marking_ref = tlp_marking.id if tlp_marking else self.tlp_marking.id

        created_by_ref = self.get_created_by_ref()

        return stix2.Indicator(
            id=indicator_id,
            name=indicator_name,
            description=f"Indicator for {observable_type}: {value}",
            pattern=pattern,
            pattern_type="stix",
            created_by_ref=created_by_ref,
            object_marking_refs=[marking_ref],
            valid_from=datetime.now(),
            external_references=external_references if external_references else None,
        )

    def create_report(
        self,
        content_id: str,
        title: str,
        description: str = "",
        published: str = None,
        modified: str = None,
        object_refs: List[str] = None,
        object_marking_refs: List[str] = None,
        labels: List[str] = None,
        custom_properties: Dict = None,
    ) -> stix2.Report:
        """
        Create a STIX Report object from CATALYST member content.

        Args:
            content_id: CATALYST member content ID
            title: Report title
            description: Report description
            published: Publication date (ISO format)
            modified: Last modified date (ISO format)
            object_refs: List of referenced object IDs
            object_marking_refs: List of marking definition IDs to apply to the report
            labels: List of labels to include in the report
            custom_properties: Dictionary of custom properties to add to the report

        Returns:
            STIX Report object
        """
        external_references = [
            stix2.ExternalReference(
                source_name=self.author_name,
                external_id=content_id,
                url=f"https://catalyst.prodaft.com/member-content/{content_id}/",
            )
        ]

        if object_refs is None:
            object_refs = []

        if object_marking_refs is None:
            object_marking_refs = [self.tlp_marking.id]

        report_props = {
            "id": Report.generate_id(title, datetime.now()),
            "name": title,
            "description": description,
            "created_by_ref": self.identity.id,
            "object_marking_refs": object_marking_refs,
            "external_references": external_references,
            "object_refs": object_refs,
            "report_types": ["threat-report"],
        }

        if published:
            report_props["published"] = published

        if modified:
            report_props["modified"] = modified

        if labels:
            report_props["labels"] = labels

        if custom_properties:
            x_properties = {}
            for key, value in custom_properties.items():
                if key.startswith("x_"):
                    x_properties[key] = value
                else:
                    x_properties[f"x_{key}"] = value

            return stix2.Report(**report_props, allow_custom=True, **x_properties)

        return stix2.Report(**report_props)

    def get_created_by_ref(self) -> str:
        """
        Return the identity ID to use as created_by_ref throughout all STIX objects. This ensures all objects reference the same identity.

        Returns:
            STIX Identity ID
        """
        return self.identity.id

    def create_detailed_threat_actor(
        self,
        threat_actor_data: Dict,
        context: str = None,
        report_reference: stix2.ExternalReference = None,
    ) -> Union[stix2.ThreatActor, stix2.IntrusionSet]:
        """
        Create a STIX Threat Actor or Intrusion Set object with full details from CATALYST API.

        Args:
            threat_actor_data: Complete threat actor data from CATALYST API
            context: Optional additional context from the reference
            report_reference: Optional reference to the report this entity is from

        Returns:
            STIX ThreatActor or IntrusionSet object with full details included
        """
        external_references = []
        if report_reference:
            external_references = [report_reference]

        # Extract the basic details
        entity_id = threat_actor_data.get("id", "")
        entity_value = threat_actor_data.get("name", "")

        # Determine the appropriate STIX object type
        is_group = threat_actor_data.get("is_group", True)
        is_abstract = threat_actor_data.get("is_abstract", False)

        # Get the description
        description = threat_actor_data.get("description", "")
        if not description:
            if is_abstract:
                description = f"Intrusion Set {entity_value} from CATALYST"
            else:
                description = f"Threat Actor {entity_value} from CATALYST"
        if context:
            description = f"{description}\n\n{context}"

        # Get aliases
        aliases = []
        if "aliases" in threat_actor_data and isinstance(
            threat_actor_data["aliases"], list
        ):
            aliases = [
                alias.get("name")
                for alias in threat_actor_data["aliases"]
                if alias.get("name")
            ]

        # Get motivation
        motivation = None
        if "motivation" in threat_actor_data and threat_actor_data["motivation"]:
            motivation = threat_actor_data["motivation"]

        custom_properties = {
            "x_catalyst_threat_actor_id": entity_id,
            "x_catalyst_is_group": is_group,
            "x_catalyst_is_abstract": is_abstract,
        }

        # Add motivation if available
        if motivation:
            custom_properties["x_catalyst_motivation"] = motivation
        # Add spoken languages
        if "spoken_languages" in threat_actor_data and isinstance(
            threat_actor_data["spoken_languages"], list
        ):
            spoken_languages = [
                lang.get("name")
                for lang in threat_actor_data["spoken_languages"]
                if lang.get("name")
            ]
            if spoken_languages:
                custom_properties["x_catalyst_spoken_languages"] = spoken_languages

        # Add suspected origins
        if "suspected_origins" in threat_actor_data and isinstance(
            threat_actor_data["suspected_origins"], list
        ):
            origins = [
                country.get("name")
                for country in threat_actor_data["suspected_origins"]
                if country.get("name")
            ]
            if origins:
                custom_properties["x_catalyst_suspected_origins"] = origins

        # Add risk information
        if "associated_risks" in threat_actor_data:
            custom_properties["x_catalyst_associated_risks"] = threat_actor_data[
                "associated_risks"
            ]

        created_by_ref = self.get_created_by_ref()

        if is_abstract:
            # Create an Intrusion Set for abstract entities
            return stix2.IntrusionSet(
                id=IntrusionSet.generate_id(entity_value),
                name=entity_value,
                description=description,
                aliases=aliases if aliases else None,
                created_by_ref=created_by_ref,
                object_marking_refs=[self.tlp_marking.id],
                external_references=(
                    external_references if external_references else None
                ),
                custom_properties=custom_properties,
            )
        else:
            # Create a Threat Actor with the appropriate type
            actor_type = "threat-actor-group" if is_group else "threat-actor-individual"
            custom_properties["x_opencti_type"] = actor_type
            return stix2.ThreatActor(
                id=ThreatActor.generate_id(entity_value, actor_type),
                name=entity_value,
                description=description,
                aliases=aliases if aliases else None,
                created_by_ref=created_by_ref,
                object_marking_refs=[self.tlp_marking.id],
                external_references=(
                    external_references if external_references else None
                ),
                custom_properties=custom_properties,
            )
