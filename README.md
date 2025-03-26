# Network Utility Toolkit

A Streamlit application providing network-related utilities including:
- MAC Address Formatting
- Random MAC Address Generation
- IP Address Lookup

## Features
### MAC Address Formatter
- Convert MAC addresses to different formats
- Support for various input styles
- Format options:
  - Colon (Cisco) style
  - Hyphen (Windows) style
  - Dot (Cisco) style
  - No Separator style

### Random MAC Address Generator
- Generate random MAC addresses
- Support for different MAC types:
  - Random
  - Unicast
  - Multicast
- Generate multiple MAC addresses at once

### IP Address Lookup
- Comprehensive IP address information retrieval
- Technical details
- Geolocation information
- ISP and ASN details

## Requirements
- Python 3.7+
- Streamlit
- Requests library

## Installation
1. Clone the repository
2. Install requirements: 
   ```
   pip install streamlit requests
   ```

## How to Run
```bash
streamlit run mac_formatter_app.py
```

## Usage
1. Choose a tab:
   - MAC Formatter: Enter a MAC address and select a format
   - MAC Generator: Choose MAC type and number of addresses
   - IP Lookup: Enter an IP address to get detailed information
2. Click the respective action button
3. View the results
