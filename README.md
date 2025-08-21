# Snyk Ignore Transfer

A Python tool for transferring and managing Snyk ignore rules across projects and repositories.

## Overview

This tool helps security teams and developers manage Snyk ignore rules by providing functionality to:
- Transfer ignore rules between Snyk projects
- Analyze and clean user data
- Generate provisioning reports
- Handle false positive identification

## Features

- **Ignore Rule Transfer**: Transfer Snyk ignore rules between projects
- **User Management**: Clean and manage Snyk user data
- **Reporting**: Generate comprehensive provisioning reports
- **False Positive Handling**: Identify and manage false positive security findings

## Requirements

- Python 3.10+
- Snyk API access
- Required packages (see `requirements.txt`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gp_ignore_transfer.git
cd gp_ignore_transfer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Main Scripts

- `snyk_ignore_transfer.py` - Main tool for transferring ignore rules
- `snyk_user_provisioning_report.py` - Generate user provisioning reports

### Configuration

Set up your Snyk API credentials as environment variables:
```bash
export SNYK_TOKEN="your-snyk-api-token"
export SNYK_ORG_ID="your-organization-id"
```

## Project Structure

```
gp_ignore_transfer/
├── snyk_ignore_transfer.py          # Main ignore transfer functionality
├── snyk_user_provisioning_report.py # User provisioning reporting
├── requirements.txt                  # Python dependencies
└── README.md                       # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review the code for implementation details

## Disclaimer

This tool is provided as-is for educational and operational purposes. Users are responsible for ensuring compliance with their organization's security policies and applicable regulations. 