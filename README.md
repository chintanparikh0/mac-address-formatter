# Network Utility Toolkit

A comprehensive network utility application built with Streamlit that provides various network-related tools and utilities.

## Features

- **MAC Address Formatter**
  - Format MAC addresses in various styles (Cisco, Windows, etc.)
  - Validate MAC addresses
  - Export formatting history

- **MAC Address Generator**
  - Generate random MAC addresses
  - Support for Unicast and Multicast addresses
  - Configurable formats

- **IP Address Tools**
  - IP address lookup with geolocation
  - Private/Public IP detection
  - Reverse DNS lookup
  - Caching support

- **Network Diagnostic Tools**
  - Port scanning with service detection
  - Ping utility
  - Rate limiting and security features

- **Cryptographic Tools**
  - Hash generation (MD5, SHA-1, SHA-256, SHA-512)
  - Secure password generation
  - Configurable character sets

- **Utility Tools**
  - Duplicate text removal
  - Store code conversion
  - Export functionality

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-utility-toolkit.git
   cd network-utility-toolkit
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

1. Start the application:
   ```bash
   streamlit run mac_formatter_app.py
   ```

2. Open your browser and navigate to the provided URL (usually http://localhost:8501)

3. Select the desired tool from the available tabs

## Configuration

The application can be configured using the `config.json` file:

- API settings (rate limits, timeouts)
- Security settings (SSL verification, allowed IP ranges)
- Cache settings (timeout, max size)
- Logging configuration
- Export settings

## Development

1. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run tests:
   ```bash
   python -m pytest
   ```

3. Run linting:
   ```bash
   flake8 .
   black .
   mypy .
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

- Uses secure random number generation
- Implements rate limiting
- Input validation and sanitization
- SSL/TLS verification
- Configurable security settings

## Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Uses [ipapi.co](https://ipapi.co/) for IP lookups
- Icons from [Streamlit](https://streamlit.io/)
