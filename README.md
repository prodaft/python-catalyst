# PRODAFT CATALYST API Client

[![PyPI version](https://badge.fury.io/py/python-catalyst.svg)](https://badge.fury.io/py/python-catalyst)
[![Python Versions](https://img.shields.io/pypi/pyversions/python-catalyst.svg)](https://pypi.org/project/python-catalyst/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/prodaft/python-catalyst/actions/workflows/python-test.yml/badge.svg)](https://github.com/prodaft/python-catalyst/actions/workflows/python-test.yml)

A Python client for the PRODAFT CATALYST API, enabling seamless integration with OpenCTI by converting threat intelligence data into STIX 2.1 format.

## Overview

This library provides a simple interface to retrieve threat intelligence from the PRODAFT CATALYST platform and convert it into STIX 2.1 format for ingestion into OpenCTI or other threat intelligence platforms.

## Key Features

- Retrieve threat intelligence from CATALYST API
- Extract entities (malware, threat actors, tools, etc.)
- Convert to STIX 2.1 format for OpenCTI integration
- Support for all CATALYST observable types
- TLP classification support (CLEAR, GREEN, AMBER, AMBER+STRICT, RED)
- Automatic pagination for large result sets
- Proxy and custom logging support

## Installation

```bash
pip install python-catalyst
```

## Requirements

- Python 3.8+
- requests
- stix2
- python-dateutil
- pycti

## Basic Usage

```python
from python_catalyst import CatalystClient, PostCategory, TLPLevel
from datetime import datetime

# Initialize client
client = CatalystClient(api_key="your_api_key")

# Get threat intelligence data
content = client.get_member_content("content_id")

# Extract entities
entities = client.extract_entities_from_member_content("content_id")

# Convert to STIX format for OpenCTI
report, stix_objects = client.create_report_from_member_content(content)
```

## Documentation

### Authentication

```python
client = CatalystClient(
    api_key="your_api_key",
    base_url="https://prod.blindspot.prodaft.com/api"
)
```

### Content Retrieval

The client supports various methods to retrieve threat intelligence:

- `get_member_content(content_id)`: Get a specific content by ID
- `get_member_contents(category, tlp, page, page_size)`: Get paginated content
- `get_all_member_contents(category, published_on_after, search)`: Get all content with automatic pagination
- `get_updated_member_contents(since, max_results)`: Get content updated since a specific date

### Entity Extraction

```python
entities = client.extract_entities_from_member_content("content_id")
```

### STIX Conversion

Convert CATALYST content to STIX 2.1 objects for OpenCTI integration:

```python
# Convert to STIX format
report, stix_objects = client.create_report_from_member_content(content)
```

## Development

### Setting up the development environment

```bash
# Clone the repository
git clone https://github.com/prodaft/python-catalyst.git
cd python-catalyst

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running tests

```bash
# Run unit tests
pytest -xvs tests/ -k "not test_integration"

# Run integration tests (requires API key)
export CATALYST_API_KEY=your_api_key
pytest -xvs tests/ --run-integration

```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For support or feature requests, please create an issue on the GitHub repository or contact PRODAFT.

## License

Distributed under the MIT License. See `LICENSE` for more information.
