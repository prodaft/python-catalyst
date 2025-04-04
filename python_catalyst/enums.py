"""Enums for the CATALYST API."""

from enum import Enum


class ObservableType(Enum):
    """Types of observables supported by the CATALYST API."""

    BTC_ADDRESS = "BTC_ADDRESS"
    URL = "URL"
    DOMAIN_NAME = "DOMAIN_NAME"
    IP_ADDRESS = "IP_ADDRESS"
    FILE_HASH_MD5 = "FILE_HASH_MD5"
    FILE_HASH_SHA1 = "FILE_HASH_SHA1"
    FILE_HASH_SHA256 = "FILE_HASH_SHA256"
    EMAIL = "EMAIL"
    JABBER_ADDRESS = "JABBER_ADDRESS"
    TOX_ADDRESS = "TOX_ADDRESS"
    TELEGRAM = "TELEGRAM"
    X = "X"


class PostCategory(Enum):
    """Categories of member content posts."""

    DISCOVERY = "DISCOVERY"
    ATTRIBUTION = "ATTRIBUTION"
    RESEARCH = "RESEARCH"
    FLASH_ALERT = "FLASH_ALERT"


class TLPLevel(Enum):
    """TLP classification levels for member content."""

    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"
