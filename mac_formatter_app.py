import streamlit as st
import re
import random
import requests
import json

def format_mac_address(mac_address):
    # Remove all possible separators
    cleaned_mac = re.sub(r'[.:\-]', '', mac_address)

    if len(cleaned_mac) == 12:
        # Lowercase formatting
        lower_ip = cleaned_mac.lower()
        hex1 = lower_ip[0:2]
        hex2 = lower_ip[2:4]
        hex3 = lower_ip[4:6]
        hex4 = lower_ip[6:8]
        hex5 = lower_ip[8:10]
        hex6 = lower_ip[10:12]

        # Uppercase formatting
        upper_ip = cleaned_mac.upper()
        hexa = upper_ip[0:2]
        hexb = upper_ip[2:4]
        hexc = upper_ip[4:6]
        hexd = upper_ip[6:8]
        hexe = upper_ip[8:10]
        hexf = upper_ip[10:12]

        # Return all formats
        return {
            'Hyphen Format (Lowercase)': f"{hex1}-{hex2}-{hex3}-{hex4}-{hex5}-{hex6}",
            'Colon Format (Lowercase)': f"{hex1}:{hex2}:{hex3}:{hex4}:{hex5}:{hex6}",
            'Continuous Format (Lowercase)': f"{hex1}{hex2}{hex3}{hex4}{hex5}{hex6}",
            'Uppercase Format': f"{hexa}{hexb}{hexc}{hexd}{hexe}{hexf}",
            'Cisco Format': f"{hexa}.{hexb}.{hexc}"
        }
    else:
        return None

def generate_random_mac(mac_type='universal'):
    """
    Generate a random MAC address.
    
    Args:
    mac_type (str): Type of MAC address
        - 'universal': Unicast, globally unique (default)
        - 'local': Locally administered
        - 'multicast': Multicast address
    
    Returns:
    str: Randomly generated MAC address
    """
    # First octet rules
    if mac_type == 'universal':
        # Unicast, globally unique: least significant bit of first octet is 0
        first_octet = random.randint(0, 127) * 2
    elif mac_type == 'local':
        # Locally administered: least significant bit of first octet is 1
        first_octet = random.randint(0, 127) * 2 + 1
    elif mac_type == 'multicast':
        # Multicast: least significant bit of first octet is 1
        first_octet = random.randint(128, 255)
    else:
        raise ValueError("Invalid MAC address type")
    
    # Generate the rest of the MAC address
    mac_parts = [first_octet] + [random.randint(0, 255) for _ in range(5)]
    
    # Convert to hex string
    mac_address = ''.join([f'{x:02x}' for x in mac_parts])
    
    return mac_address

def validate_ip_address(ip):
    """
    Validate IP address format
    """
    # Regular expression for IPv4 validation
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if not re.match(ip_pattern, ip):
        return False
    
    # Additional check for valid octets
    octets = ip.split('.')
    for octet in octets:
        if not (0 <= int(octet) <= 255):
            return False
    
    return True

def lookup_ip_details(ip_address):
    """
    Lookup IP address details using ipapi.co
    """
    try:
        # Primary API for IP lookup
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        
        # Fallback API if primary fails
        if response.status_code != 200:
            response = requests.get(f'https://ip-api.com/json/{ip_address}')
        
        # Parse the response
        data = response.json()
        
        # Normalize the data structure
        if 'error' in data:
            return None
        
        # Extract relevant information
        details = {
            'IP Address': ip_address,
            'City': data.get('city', 'N/A'),
            'Region': data.get('region', 'N/A'),
            'Country': data.get('country_name', data.get('country', 'N/A')),
            'Continent': data.get('continent_code', 'N/A'),
            'Latitude': data.get('latitude', 'N/A'),
            'Longitude': data.get('longitude', 'N/A'),
            'ISP': data.get('org', data.get('isp', 'N/A')),
            'Timezone': data.get('timezone', 'N/A'),
            'Postal Code': data.get('postal', data.get('zip', 'N/A'))
        }
        
        return details
    
    except Exception as e:
        st.error(f"Error looking up IP details: {e}")
        return None

def main():
    st.set_page_config(page_title="Network Utility Tool", page_icon="🌐")
    
    st.title('🌐 Network Utility Tool')
    st.markdown("MAC Address Formatter, Random MAC Generator, and IP Lookup")
    
    # Create tabs for different functionalities
    tab1, tab2, tab3 = st.tabs([
        "Format MAC Address", 
        "Generate Random MAC", 
        "IP Address Lookup"
    ])
    
    with tab1:
        # MAC Address Formatting
        mac_address = st.text_input('Enter MAC Address', 
                                    placeholder='00:11:22:33:44:55 or 001122334455', 
                                    key='format_input',
                                    help='Input MAC address with or without separators')
        
        if st.button('Format MAC Address', type='primary', key='format_button'):
            if mac_address:
                formatted_macs = format_mac_address(mac_address)
                
                if formatted_macs:
                    st.success('MAC Address Formatted Successfully! 🎉')
                    
                    # Display formatted MAC addresses
                    for format_name, formatted_mac in formatted_macs.items():
                        st.write(f"{format_name}: {formatted_mac}")
                else:
                    st.error('Invalid MAC Address. Please enter a 12-character MAC address.')
            else:
                st.warning('Please enter a MAC address.')
    
    with tab2:
        # Random MAC Address Generation
        st.subheader("Generate Random MAC Address")
        
        mac_type = st.selectbox(
            "Select MAC Address Type",
            ["Universal (Unicast)", "Locally Administered", "Multicast"],
            help="Choose the type of MAC address to generate"
        )
        
        type_mapping = {
            "Universal (Unicast)": "universal",
            "Locally Administered": "local", 
            "Multicast": "multicast"
        }
        
        if st.button('Generate MAC Address', type='primary', key='generate_button'):
            try:
                # Generate MAC address
                random_mac = generate_random_mac(type_mapping[mac_type])
                
                # Format the generated MAC
                formatted_macs = format_mac_address(random_mac)
                
                st.success('Random MAC Address Generated! 🎲')
                
                # Display formatted MAC addresses
                for format_name, formatted_mac in formatted_macs.items():
                    st.write(f"{format_name}: {formatted_mac}")
            
            except Exception as e:
                st.error(f"Error generating MAC address: {e}")
    
    with tab3:
        # IP Address Lookup
        st.subheader("IP Address Lookup")
        
        # IP Address input
        ip_address = st.text_input(
            'Enter IP Address', 
            placeholder='e.g., 8.8.8.8', 
            key='ip_lookup_input',
            help='Enter a valid IPv4 address'
        )
        
        # Lookup button
        if st.button('Lookup IP Details', type='primary', key='ip_lookup_button'):
            # Validate IP address
            if not ip_address:
                st.warning('Please enter an IP address.')
            elif not validate_ip_address(ip_address):
                st.error('Invalid IP Address. Please enter a valid IPv4 address.')
            else:
                # Perform IP Lookup
                ip_details = lookup_ip_details(ip_address)
                
                if ip_details:
                    st.success('IP Details Retrieved Successfully! 🌍')
                    
                    # Display IP details in a more readable format
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Location Details:**")
                        st.write(f"City: {ip_details['City']}")
                        st.write(f"Region: {ip_details['Region']}")
                        st.write(f"Country: {ip_details['Country']}")
                        st.write(f"Continent: {ip_details['Continent']}")
                        st.write(f"Postal Code: {ip_details['Postal Code']}")
                    
                    with col2:
                        st.markdown("**Network Details:**")
                        st.write(f"IP Address: {ip_details['IP Address']}")
                        st.write(f"ISP: {ip_details['ISP']}")
                        st.write(f"Timezone: {ip_details['Timezone']}")
                        st.write(f"Latitude: {ip_details['Latitude']}")
                        st.write(f"Longitude: {ip_details['Longitude']}")
                else:
                    st.error('Unable to retrieve IP details. Please try again.')
    
    # Sidebar information
    st.sidebar.header("About Network Utilities")
    st.sidebar.info("""
    Network Utility Tool Features:
    
    1. MAC Address Formatter
    - Convert MAC addresses to multiple formats
    - Support for various input styles
    
    2. Random MAC Generator
    - Generate MAC addresses of different types
    - Universal, Locally Administered, Multicast
    
    3. IP Address Lookup
    - Retrieve geolocation details
    - Get ISP and network information
    
    Note: IP lookup requires an active internet connection.
    """)

if __name__ == '__main__':
    main()
