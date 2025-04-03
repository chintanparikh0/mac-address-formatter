#!/usr/bin/env python3
# Network Utility Toolkit - A comprehensive network utility application
# Author: [ChintanParikh]
# Version: 1.0.0

# Standard library imports
import streamlit as st
import requests
import socket
import ipaddress
import re
import random
import subprocess
import platform
import time
import logging
import json
import os
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Tuple, Union, Optional
import secrets
import string
import ssl
import csv
import pathlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
MAX_PORT_RANGE = 1000
API_RATE_LIMIT = 1  # seconds
SCAN_RATE_LIMIT = 0.1  # seconds
CACHE_TIMEOUT = 3600  # 1 hour
MAX_RETRIES = 3

# Load configuration
def load_config() -> dict:
    """Load configuration from config.json"""
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
    return {}

CONFIG = load_config()

# Cache decorator for API calls
def rate_limited_cache(seconds: int = API_RATE_LIMIT):
    """
    Decorator that combines rate limiting and caching
    Args:
        seconds (int): Rate limit in seconds
    """
    def decorator(func):
        cache = {}
        last_called = {}
        
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            current_time = time.time()
            
            # Check cache
            if key in cache:
                if current_time - cache[key]['timestamp'] < CACHE_TIMEOUT:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cache[key]['result']
            
            # Rate limiting
            if key in last_called:
                time_since_last_call = current_time - last_called[key]
                if time_since_last_call < seconds:
                    time.sleep(seconds - time_since_last_call)
            
            # Call function
            result = func(*args, **kwargs)
            
            # Update cache and timestamp
            cache[key] = {
                'result': result,
                'timestamp': current_time
            }
            last_called[key] = current_time
            
            return result
        return wrapper
    return decorator

class NetworkUtilityError(Exception):
    """Base exception class for Network Utility errors"""
    pass

class ValidationError(NetworkUtilityError):
    """Validation error exception"""
    pass

class APIError(NetworkUtilityError):
    """API error exception"""
    pass

class ExportManager:
    """Manages data export functionality"""
    
    def __init__(self):
        self.export_path = pathlib.Path(CONFIG.get('export', {}).get('default_path', 'exports'))
        self.export_path.mkdir(exist_ok=True)
        
    def export_data(self, data: Union[List, Dict], format: str, prefix: str = '') -> str:
        """
        Export data to file in specified format
        Args:
            data: Data to export
            format: Export format (csv, json, txt)
            prefix: Filename prefix
        Returns:
            str: Path to exported file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{prefix}_{timestamp}.{format}" if prefix else f"export_{timestamp}.{format}"
        filepath = self.export_path / filename
        
        try:
            if format == 'json':
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            elif format == 'csv':
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)
                else:
                    raise ValueError("Data must be a list of dictionaries for CSV export")
            elif format == 'txt':
                with open(filepath, 'w') as f:
                    if isinstance(data, (list, tuple)):
                        f.write('\n'.join(map(str, data)))
                    else:
                        f.write(str(data))
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            logger.info(f"Data exported to {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            raise

# Create export manager instance
export_manager = ExportManager()

def validate_mac_address(mac: str) -> bool:
    """
    Validate MAC address in various formats with enhanced validation
    Args:
        mac (str): MAC address to validate
    Returns:
        bool: True if valid, False otherwise
    """
    if not mac:
        logger.debug("Empty MAC address")
        return False
        
    try:
        # Remove any separators and whitespace
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').replace(' ', '')
        
        # Basic format check
        if not re.match(r'^[0-9A-Fa-f]{12}$', mac_clean):
            logger.debug(f"Invalid MAC format: {mac}")
            return False
            
        # Check for valid OUI (first 6 characters)
        oui = mac_clean[:6].upper()
        if all(x == '0' for x in oui) or all(x == 'F' for x in oui):
            logger.debug(f"Invalid OUI in MAC: {mac}")
            return False
            
        # Additional checks for common errors
        mac_parts = [mac_clean[i:i+2] for i in range(0, 12, 2)]
        if all(part == mac_parts[0] for part in mac_parts):
            logger.debug(f"MAC contains repeated octets: {mac}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"MAC validation error: {e}")
        return False

def format_mac_address(mac: str, format_type: str) -> str:
    """
    Format MAC address to different styles with validation
    Args:
        mac (str): MAC address to format
        format_type (str): Desired format type
    Returns:
        str: Formatted MAC address
    Raises:
        ValidationError: If MAC address is invalid
    """
    try:
        # Validate input
        if not validate_mac_address(mac):
            raise ValidationError(f"Invalid MAC address: {mac}")
        
        # Remove any existing separators and convert to lowercase
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').replace(' ', '').lower()
        
        # Format mapping
        formats = {
            'Colon (Cisco)': ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper(),
            'Hyphen (Windows)': '-'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper(),
            'Dot (Cisco)': '.'.join(mac_clean[i:i+4] for i in range(0, 12, 4)).upper(),
            'No Separator (Uppercase)': mac_clean.upper(),
            'No Separator (Lowercase)': mac_clean.lower(),
            'Colon (Lowercase)': ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)),
            'Hyphen (Lowercase)': '-'.join(mac_clean[i:i+2] for i in range(0, 12, 2)),
            'Dot (Lowercase)': '.'.join(mac_clean[i:i+4] for i in range(0, 12, 4))
        }
        
        if format_type not in formats:
            raise ValidationError(f"Invalid format type: {format_type}")
            
        formatted_mac = formats[format_type]
        logger.debug(f"Formatted MAC {mac} to {formatted_mac} ({format_type})")
        return formatted_mac
        
    except Exception as e:
        logger.error(f"MAC formatting error: {e}")
        raise

def generate_random_mac(mac_type: str = 'Random') -> str:
    """
    Generate a random MAC address with proper unicast/multicast bit
    Args:
        mac_type (str): Type of MAC address ('Random', 'Unicast', or 'Multicast')
    Returns:
        str: Generated MAC address in uppercase hexadecimal
    """
    try:
        # Generate first byte based on type
        if mac_type == 'Unicast':
            # Set least significant bit of first byte to 0 for unicast
            first_byte = secrets.randbelow(256) & 0xFE  # Clear last bit
        elif mac_type == 'Multicast':
            # Set least significant bit of first byte to 1 for multicast
            first_byte = secrets.randbelow(256) | 0x01  # Set last bit
        else:  # Random
            first_byte = secrets.randbelow(256)
        
        # Generate remaining bytes
        remaining_bytes = [secrets.randbelow(256) for _ in range(5)]
        
        # Combine all bytes and format as hex
        mac_bytes = [first_byte] + remaining_bytes
        mac = ''.join(f"{b:02X}" for b in mac_bytes)
        
        logger.debug(f"Generated {mac_type} MAC address: {mac}")
        return mac
        
    except Exception as e:
        logger.error(f"Error generating MAC address: {e}")
        raise

def validate_ip_address(ip):
    """
    Validate IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    """
    Check if an IP address is private or public
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return None

def get_reverse_hostname(ip):
    """
    Get reverse DNS lookup for an IP address
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "N/A"

def comprehensive_ip_lookup(ip_address):
    """
    Perform comprehensive IP address lookup with error handling and rate limiting
    Args:
        ip_address (str): IP address to lookup
    Returns:
        dict: Dictionary containing IP details or None if lookup fails
    """
    # Add rate limiting to prevent API abuse
    time.sleep(1)  # Basic rate limiting

    # Detailed IP lookup results dictionary
    ip_details = {
        'technical': {},
        'location': {},
        'asn': {},
        'country': {}
    }

    try:
        # Technical Details - These operations are safe and don't require external APIs
        ip_details['technical']['ip'] = ip_address
        ip_details['technical']['hostname'] = get_reverse_hostname(ip_address)
        ip_details['technical']['type'] = 'Public' if not is_private_ip(ip_address) else 'Private'
        ip_details['technical']['cidr'] = f"{ip_address}/24"

        # IP API Lookups with error handling and timeouts
        try:
            # Primary API - ipapi.co with timeout
            response1 = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
            
            # Backup API - ip-api.com with timeout
            response2 = requests.get(f'https://ip-api.com/json/{ip_address}', timeout=5)

            # Combine results with validation
            data1 = response1.json() if response1.status_code == 200 else {}
            data2 = response2.json() if response2.status_code == 200 else {}

            # Location Details with data validation
            ip_details['location'] = {
                'city': data1.get('city', data2.get('city', 'N/A')),
                'city_confidence': '1%',
                'metro_code': data1.get('metro_code', 'N/A'),
                'subdivision': data1.get('region', data2.get('regionName', 'N/A')),
                'subdivision_confidence': '80%',
                'country': data1.get('country_name', data2.get('country', 'N/A')),
                'country_confidence': '99%',
                'postal_code': data1.get('postal', 'N/A'),
                'postal_confidence': '1%',
                'continent': data1.get('continent_code', data2.get('continent', 'N/A')),
                'timezone': data1.get('timezone', data2.get('timezone', 'N/A')),
            }

            # ASN and ISP Details with data validation
            ip_details['asn'] = {
                'isp': data1.get('org', data2.get('isp', 'N/A')),
                'organization': data1.get('org', data2.get('org', 'N/A')),
                'user_type': 'cellular',
                'asn_number': data1.get('asn', 'N/A'),
                'anonymous_proxy': 'No',
                'satellite_provider': 'No'
            }

            # Country Details
            ip_details['country'] = {
                'registered_country': data1.get('country_name', data2.get('country', 'N/A')),
                'represented_country': 'Not Provided'
            }

            # Geolocation with data validation
            ip_details['geolocation'] = {
                'latitude': data1.get('latitude', data2.get('lat', 'N/A')),
                'longitude': data1.get('longitude', data2.get('lon', 'N/A')),
                'accuracy_radius': '20 km'
            }

        except requests.exceptions.Timeout:
            st.error("API request timed out. Please try again later.")
            return None
        except requests.exceptions.RequestException as e:
            st.error(f"API request failed: {str(e)}")
            return None

        return ip_details

    except Exception as e:
        st.error(f"Error in IP lookup: {str(e)}")
        return None

def perform_ping(host, count=4):
    """
    Perform ping operation with enhanced error handling and security
    Args:
        host (str): Host to ping
        count (int): Number of pings to send
    Returns:
        str: Ping results or error message
    """
    try:
        # Input validation
        if not host:
            return "Error: No host specified"
        
        # Basic input sanitization
        host = re.sub(r'[;&|]', '', host)  # Remove potentially dangerous characters
        
        # Validate hostname/IP
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return f"Error: Could not resolve hostname {host}"

        # Set timeout for the ping command
        timeout = 10  # seconds
        
        # Determine OS and construct appropriate ping command
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        # Construct command with input validation
        command = ['ping', param, str(min(count, 10)), host]  # Limit count to 10
        
        # Run ping with timeout
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping to {host} timed out after {timeout} seconds"
        except subprocess.CalledProcessError as e:
            return f"Ping failed: {e.stderr}"
        
    except Exception as e:
        return f"Error performing ping: {str(e)}"

def port_scan(host, start_port=1, end_port=1024):
    """
    Perform basic port scanning with enhanced error handling and rate limiting
    Args:
        host (str): Target host to scan
        start_port (int): Starting port number (1-65535)
        end_port (int): Ending port number (1-65535)
    Returns:
        list: List of open ports or error message
    """
    # Input validation
    if not host:
        return "Error: No host specified"
    
    # Validate port ranges
    start_port = max(1, min(start_port, 65535))
    end_port = max(1, min(end_port, 65535))
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    
    # Limit scan range for safety
    if end_port - start_port > 1000:
        return "Error: Port range too large. Please limit to 1000 ports at a time."
    
    try:
        # Resolve hostname to IP with timeout
        try:
            host_ip = socket.gethostbyname(host)
        except socket.gaierror:
            return f"Error: Could not resolve hostname {host}"
        
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                # Add rate limiting
                time.sleep(0.1)  # 100ms delay between ports
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    # Try to get service name
                    try:
                        service = socket.getservbyport(port)
                    except (socket.error, OSError):
                        service = "unknown"
                    open_ports.append((port, service))
                sock.close()
            except Exception as e:
                st.warning(f"Error scanning port {port}: {str(e)}")
            
            # Add progress indicator
            if (port - start_port) % 10 == 0:
                progress = (port - start_port) / (end_port - start_port)
                st.progress(progress)
        
        return open_ports
    
    except Exception as e:
        return f"Error during port scan: {str(e)}"

def generate_hash(text, hash_type='SHA-256'):
    """
    Generate cryptographic hash for given text
    Args:
        text (str): Text to hash
        hash_type (str): Type of hash algorithm to use
    Returns:
        str: Hexadecimal hash string
    """
    import hashlib
    
    # Validate input
    if not text:
        return "Error: No text provided"
    
    hash_types = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256,
        'SHA-512': hashlib.sha512
    }
    
    # Validate hash type
    if hash_type not in hash_types:
        return f"Error: Unsupported hash type. Supported types: {', '.join(hash_types.keys())}"
    
    try:
        hash_func = hash_types[hash_type]
        return hash_func(text.encode()).hexdigest()
    except Exception as e:
        return f"Error generating hash: {str(e)}"

def generate_password(length=12, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_symbols=True):
    """
    Generate a cryptographically secure random password
    Args:
        length (int): Password length (6-32 characters)
        use_uppercase (bool): Include uppercase letters
        use_lowercase (bool): Include lowercase letters
        use_digits (bool): Include digits
        use_symbols (bool): Include special characters
    Returns:
        str: Generated password or error message
    """
    import string
    import secrets  # More secure than random
    
    # Validate length
    length = max(6, min(length, 32))  # Ensure length is between 6 and 32
    
    # Build character set
    character_set = ''
    if use_uppercase:
        character_set += string.ascii_uppercase
    if use_lowercase:
        character_set += string.ascii_lowercase
    if use_digits:
        character_set += string.digits
    if use_symbols:
        character_set += "!@#$%^&*()_+-=[]{}|;:,.<>?"  # Custom safe symbols
    
    if not character_set:
        return "Error: No character types selected"
    
    try:
        # Generate password ensuring at least one character from each selected type
        password = []
        
        # Add one character from each selected type
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill the rest with random characters
        remaining_length = length - len(password)
        password.extend(secrets.choice(character_set) for _ in range(remaining_length))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    except Exception as e:
        return f"Error generating password: {str(e)}"

def remove_duplicates(text: str, case_sensitive: bool = True, ignore_whitespace: bool = False) -> Tuple[str, int, Dict[str, int]]:
    """
    Remove duplicate entries from text with enhanced handling
    Args:
        text (str): Text with entries separated by newlines
        case_sensitive (bool): Whether to treat case differently
        ignore_whitespace (bool): Whether to ignore leading/trailing whitespace
    Returns:
        tuple: (unique_entries, removed_count, stats)
    """
    if not text:
        return "", 0, {"input_count": 0, "output_count": 0, "removed_count": 0, "reduction_percentage": 0}
    
    try:
        # Split by newlines and filter out empty lines
        lines = [line for line in text.split('\n') if line.strip()]
        
        # Process lines according to settings
        processed_lines = []
        for line in lines:
            # Process the line based on settings
            if ignore_whitespace:
                line = line.strip()
            # Create a key for comparison and store original line
            key = line.lower() if not case_sensitive else line
            processed_lines.append((key, line))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_entries = []
        for key, original in processed_lines:
            if key not in seen:
                seen.add(key)
                unique_entries.append(original)
        
        # Calculate statistics
        input_count = len(lines)
        output_count = len(unique_entries)
        removed_count = input_count - output_count
        reduction_percentage = round((removed_count / input_count * 100), 2) if input_count > 0 else 0
        
        stats = {
            "input_count": input_count,
            "output_count": output_count,
            "removed_count": removed_count,
            "reduction_percentage": reduction_percentage
        }
        
        logger.debug(f"Removed {removed_count} duplicates from {input_count} entries")
        return '\n'.join(unique_entries), removed_count, stats
        
    except Exception as e:
        logger.error(f"Error removing duplicates: {e}")
        raise

def convert_store_code(store_code):
    """
    Convert alphanumeric store code to numeric code
    For example, A147 becomes 10147
    
    Args:
        store_code (str): Alphanumeric store code (e.g., A147)
        
    Returns:
        str: Numeric store code (e.g., 10147)
    """
    if not store_code:
        return ""
    
    # Define the mapping from letters to numbers
    letter_map = {
        'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15,
        'G': 16, 'H': 17, 'I': 18, 'J': 19, 'K': 20, 'L': 21,
        'M': 22, 'N': 23, 'O': 24, 'P': 25, 'Q': 26, 'R': 27,
        'S': 28, 'T': 29, 'U': 30, 'V': 31, 'W': 32, 'X': 33,
        'Y': 34, 'Z': 35
    }
    
    # Extract the first letter (if exists) and the remaining digits
    match = re.match(r'^([A-Za-z])(.*)$', store_code)
    
    if match:
        letter, rest = match.groups()
        letter = letter.upper()
        
        if letter in letter_map:
            return str(letter_map[letter]) + rest
    
    # If no match or the letter isn't in our map, return the original
    return store_code

def get_letter_number_map():
    """
    Get the mapping of letters to numbers
    
    Returns:
        dict: Letter to number mapping
    """
    return {
        'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15,
        'G': 16, 'H': 17, 'I': 18, 'J': 19, 'K': 20, 'L': 21,
        'M': 22, 'N': 23, 'O': 24, 'P': 25, 'Q': 26, 'R': 27,
        'S': 28, 'T': 29, 'U': 30, 'V': 31, 'W': 32, 'X': 33,
        'Y': 34, 'Z': 35
    }

def modify_mac_formatter_tab(tab1):
    """MAC Formatter tab with export functionality"""
    with tab1:
        st.subheader("MAC Address Formatter")
        
        # Input area
        mac_address = st.text_input(
            'Enter MAC Address', 
            placeholder='e.g., 00:11:22:33:44:55 or 00-11-22-33-44-55', 
            key='mac_input',
            help='Enter a valid MAC address'
        )
        
        format_options = [
            'Colon (Cisco)', 
            'Hyphen (Windows)', 
            'Dot (Cisco)', 
            'No Separator (Uppercase)',
            'No Separator (Lowercase)',
            'Colon (Lowercase)', 
            'Hyphen (Lowercase)', 
            'Dot (Lowercase)'
        ]
        selected_format = st.selectbox('Select Format', format_options)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button('Format MAC Address', type='primary', key='format_mac_button'):
                try:
                    if not mac_address:
                        st.warning('Please enter a MAC address.')
                    elif not validate_mac_address(mac_address):
                        st.error('Invalid MAC Address. Please enter a valid MAC address.')
                    else:
                        formatted_mac = format_mac_address(mac_address, selected_format)
                        st.success('MAC Address Formatted Successfully! 🖥️')
                        st.code(formatted_mac, language='text')
                        
                        # Add to session state history
                        if 'mac_history' not in st.session_state:
                            st.session_state.mac_history = []
                        st.session_state.mac_history.append({
                            'original': mac_address,
                            'formatted': formatted_mac,
                            'format': selected_format,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except Exception as e:
                    st.error(f"Error: {str(e)}")
        
        with col2:
            if st.button('Export History', key='export_mac_history'):
                if 'mac_history' in st.session_state and st.session_state.mac_history:
                    try:
                        export_path = export_manager.export_data(
                            st.session_state.mac_history,
                            'csv',
                            'mac_history'
                        )
                        st.success(f'History exported to {export_path}')
                    except Exception as e:
                        st.error(f"Export failed: {str(e)}")
                else:
                    st.warning('No history to export.')

def modify_mac_generator_tab(tab2):
    with tab2:
        st.subheader("Random MAC Address Generator")
        
        mac_type_options = ['Random', 'Unicast', 'Multicast']
        selected_mac_type = st.selectbox('Select MAC Address Type', mac_type_options)
        
        num_macs = st.slider('Number of MAC Addresses', min_value=1, max_value=10, value=1)
        
        if st.button('Generate MAC Addresses', type='primary', key='generate_mac_button'):
            generated_macs = [generate_random_mac(selected_mac_type) for _ in range(num_macs)]
            
            st.success(f'{num_macs} MAC Address(es) Generated Successfully! 🌐')
            for mac in generated_macs:
                col1, col2, col2b, col3, col4 = st.columns(5)
                with col1:
                    st.write("Colon (Cisco):")
                    st.code(':'.join(mac[i:i+2] for i in range(0, 12, 2)), language='text')
                with col2:
                    st.write("Hyphen:")
                    st.code('-'.join(mac[i:i+2] for i in range(0, 12, 2)), language='text')
                with col2b:
                    st.write("Dot:")
                    st.code('.'.join(mac[i:i+4] for i in range(0, 12, 4)), language='text')
                with col3:
                    st.write("Uppercase:")
                    st.code(mac, language='text')
                with col4:
                    st.write("Lowercase:")
                    st.code(mac.lower(), language='text')

def modify_ip_lookup_tab(tab3):
    with tab3:
        st.subheader("IP Address Lookup")
        
        ip_address = st.text_input(
            'Enter IP Address', 
            placeholder='e.g., 8.8.8.8', 
            key='ip_lookup_input',
            help='Enter a valid IPv4 address'
        )
        
        if st.button('Lookup IP Details', type='primary', key='ip_lookup_button'):
            if not ip_address:
                st.warning('Please enter an IP address.')
            elif not validate_ip_address(ip_address):
                st.error('Invalid IP Address. Please enter a valid IPv4 address.')
            else:
                ip_details = comprehensive_ip_lookup(ip_address)
                
                if ip_details:
                    st.success('IP Details Retrieved Successfully! 🌍')
                    
                    # Technical Details
                    st.subheader("Technical Details")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**IP Address:** {ip_details['technical']['ip']}")
                        st.write(f"**Hostname:** {ip_details['technical']['hostname']}")
                    with col2:
                        st.write(f"**Type:** {ip_details['technical']['type']}")
                        st.write(f"**CIDR:** {ip_details['technical']['cidr']}")

                    # Location Details
                    st.subheader("Location Details")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**City:** {ip_details['location']['city']} *(1% confidence)*")
                        st.write(f"**Subdivision:** {ip_details['location']['subdivision']} *(80% confidence)*")
                        st.write(f"**Postal Code:** {ip_details['location']['postal_code']} *(1% confidence)*")
                    with col2:
                        st.write(f"**Country:** {ip_details['location']['country']} *(99% confidence)*")
                        st.write(f"**Continent:** {ip_details['location']['continent']}")
                        st.write(f"**Timezone:** {ip_details['location']['timezone']}")

def modify_network_tools_tab(tab4):
    with tab4:
        st.subheader("Network Diagnostic Tools")
        
        tool_options = ['Ping', 'Port Scan', 'Hash Generator', 'Password Generator']
        selected_tool = st.selectbox('Select Network Tool', tool_options)
        
        if selected_tool == 'Ping':
            host = st.text_input('Enter Host/IP to Ping', placeholder='e.g., google.com')
            ping_count = st.slider('Number of Pings', min_value=1, max_value=10, value=4)
            
            if st.button('Perform Ping'):
                # Add a warning about server-side execution
                st.warning("Note: Ping is performed from Streamlit's server, which may have network limitations. Results may vary.")
                
                result = perform_ping(host, ping_count)
                st.code(result, language='text')
        
        elif selected_tool == 'Port Scan':
            host = st.text_input('Enter Host/IP to Scan', placeholder='e.g., scanme.nmap.org')
            start_port = st.number_input('Start Port', min_value=1, max_value=65535, value=1)
            end_port = st.number_input('End Port', min_value=1, max_value=65535, value=1024)
            
            if st.button('Scan Ports'):
                # Add a warning about server-side execution
                st.warning("Note: Port scan is performed from Streamlit's server, which may have network limitations. Results may vary.")
                
                open_ports = port_scan(host, start_port, end_port)
                if isinstance(open_ports, list):
                    if open_ports:
                        st.success(f"Open Ports: {open_ports}")
                    else:
                        st.warning("No open ports found.")
                else:
                    st.error(open_ports)
        
        elif selected_tool == 'Hash Generator':
            hash_input = st.text_input('Enter Text to Hash')
            hash_type = st.selectbox('Hash Type', ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'])
            
            if st.button('Generate Hash'):
                hash_result = generate_hash(hash_input, hash_type)
                st.code(f"{hash_type} Hash: {hash_result}", language='text')
        
        elif selected_tool == 'Password Generator':
            length = st.slider('Password Length', min_value=6, max_value=32, value=12)
            
            use_uppercase = st.checkbox('Include Uppercase', value=True)
            use_lowercase = st.checkbox('Include Lowercase', value=True)
            use_digits = st.checkbox('Include Digits', value=True)
            use_symbols = st.checkbox('Include Symbols', value=True)
            
            if st.button('Generate Password'):
                password = generate_password(
                    length, 
                    use_uppercase, 
                    use_lowercase, 
                    use_digits, 
                    use_symbols
                )
                st.code(f"Generated Password: {password}", language='text')

def modify_duplicate_remover_tab(tab5):
    with tab5:
        st.subheader("Duplicate Remover")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            text_input = st.text_area(
                'Enter text with duplicate entries (one per line)',
                height=300,
                placeholder='Enter items here, one per line...',
                help='Each line will be treated as a separate entry'
            )
        
        with col2:
            st.write("**Options:**")
            case_sensitive = st.checkbox('Case Sensitive', value=True, 
                                        help='When checked, "ABC" and "abc" are treated as different entries')
            ignore_whitespace = st.checkbox('Ignore Whitespace', value=True, 
                                           help='When checked, leading and trailing whitespace are ignored')
            
            st.write("**Example:**")
            example_text = """apple
APPLE
banana
banana
  cherry  
cherry"""
            st.code(example_text, language='text')
            
            st.write("With default options, this would keep: apple, APPLE, banana, cherry")
        
        if st.button('Remove Duplicates', type='primary'):
            if not text_input:
                st.warning('Please enter some text.')
            else:
                unique_text, removed_count, stats = remove_duplicates(
                    text_input, 
                    case_sensitive=case_sensitive, 
                    ignore_whitespace=ignore_whitespace
                )
                
                st.success(f'Duplicates Removed Successfully! Found {stats["removed_count"]} duplicates. 🧹')
                
                # Display statistics
                st.subheader("Results")
                cols = st.columns(4)
                cols[0].metric("Input Items", stats["input_count"])
                cols[1].metric("Unique Items", stats["output_count"])
                cols[2].metric("Removed", stats["removed_count"])
                cols[3].metric("Reduction", f"{stats['reduction_percentage']}%")
                
                # Display result
                st.text_area("Unique Entries:", value=unique_text, height=250)
                
                # Copy to clipboard button (implemented as a download button since Streamlit doesn't have direct clipboard access)
                st.download_button(
                    label="📋 Copy to Clipboard",
                    data=unique_text,
                    file_name="unique_entries.txt",
                    mime="text/plain"
                )

def modify_store_code_converter_tab(tab6):
    with tab6:
        st.subheader("Store Code Converter")
        
        col1, col2 = st.columns([3, 2])
        
        with col1:
            store_code = st.text_input(
                'Enter Store Code',
                placeholder='e.g., A147',
                help='Enter an alphanumeric store code starting with a letter'
            )
            
            if st.button('Convert Store Code', type='primary'):
                if not store_code:
                    st.warning('Please enter a store code.')
                else:
                    numeric_code = convert_store_code(store_code)
                    
                    if numeric_code == store_code:
                        st.warning('The input does not match the expected format (letter followed by digits) or the letter is not in the range A-Z.')
                    else:
                        st.success('Store Code Converted Successfully! 🏪')
                        st.markdown(f"### {store_code} → {numeric_code}")
            
            # Option to process multiple codes at once
            st.markdown("---")
            st.subheader("Batch Conversion")
            
            batch_input = st.text_area(
                'Enter multiple store codes (one per line)',
                height=150,
                placeholder='A147\nB201\nC305',
                help='Each line will be treated as a separate store code'
            )
            
            if st.button('Convert All Codes', type='primary'):
                if not batch_input:
                    st.warning('Please enter store codes to convert.')
                else:
                    # Process each line
                    lines = batch_input.strip().split('\n')
                    results = []
                    
                    for line in lines:
                        if line.strip():
                            numeric = convert_store_code(line.strip())
                            results.append((line.strip(), numeric))
                    
                    # Display results in a table
                    if results:
                        st.success(f'Converted {len(results)} store codes successfully! 🏪')
                        
                        # Create a DataFrame for display
                        import pandas as pd
                        df = pd.DataFrame(results, columns=['Original Code', 'Numeric Code'])
                        st.dataframe(df)
                        
                        # Copy results button
                        result_text = '\n'.join([f"{orig} → {num}" for orig, num in results])
                        st.download_button(
                            label="📋 Copy Results",
                            data=result_text,
                            file_name="converted_codes.txt",
                            mime="text/plain"
                        )
        
        with col2:
            st.markdown("### Reference Chart")
            st.markdown("This table shows the numeric value for each letter:")
            
            # Display the letter to number mapping
            letter_map = get_letter_number_map()
            
            # Create rows of 5 items each for better display
            rows = []
            current_row = []
            
            for letter, number in letter_map.items():
                current_row.append(f"{letter} = {number}")
                if len(current_row) == 5:
                    rows.append(current_row)
                    current_row = []
            
            if current_row:  # Add any remaining items
                rows.append(current_row)
            
            # Display the reference table
            for row in rows:
                st.markdown(" | ".join(row))
            
            st.markdown("---")
            st.markdown("### Examples")
            examples = [
                ('A147', '10147'),
                ('B220', '11220'),
                ('C333', '12333'),
                ('Z999', '35999')
            ]
            
            for orig, conv in examples:
                st.markdown(f"**{orig}** → **{conv}**")

def main():
    """
    Main application entry point with error handling and session state management
    """
    try:
        # Configure Streamlit page
        st.set_page_config(
            page_title='Network Utility Toolkit',
            page_icon='🌐',
            layout='wide',
            initial_sidebar_state='expanded'
        )
        
        # Initialize session state if needed
        if 'history' not in st.session_state:
            st.session_state.history = []
        
        st.title('🌐 Network Utility Toolkit')
        
        # Create tabs with error handling
        try:
            tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                'MAC Formatter', 
                'MAC Generator', 
                'IP Lookup', 
                'Network Tools',
                'Duplicate Remover',
                'Store Code Converter'
            ])
            
            # Populate tabs with error handling
            modify_mac_formatter_tab(tab1)
            modify_mac_generator_tab(tab2)
            modify_ip_lookup_tab(tab3)
            modify_network_tools_tab(tab4)
            modify_duplicate_remover_tab(tab5)
            modify_store_code_converter_tab(tab6)
            
        except Exception as tab_error:
            st.error(f"Error creating tabs: {str(tab_error)}")
            
    except Exception as e:
        st.error(f"Application error: {str(e)}")

if __name__ == '__main__':
    main()
