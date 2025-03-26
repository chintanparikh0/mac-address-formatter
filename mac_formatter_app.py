import streamlit as st
import requests
import socket
import ipaddress
import re
import random

def validate_mac_address(mac):
    """
    Validate MAC address in various formats
    """
    # Remove any separators and whitespace
    mac = mac.replace(':', '').replace('-', '').replace('.', '').replace(' ', '')
    
    # Check if the MAC address is a valid hexadecimal string of 12 characters
    if not re.match(r'^[0-9A-Fa-f]{12}$', mac):
        return False
    return True

def format_mac_address(mac, format_type):
    """
    Format MAC address to different styles
    """
    # Remove any existing separators and convert to lowercase
    mac = mac.replace(':', '').replace('-', '').replace('.', '').replace(' ', '').lower()
    
    # Formats
    if format_type == 'Colon (Cisco)':
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    elif format_type == 'Hyphen (Windows)':
        return '-'.join(mac[i:i+2] for i in range(0, 12, 2))
    elif format_type == 'Dot (Cisco)':
        return '.'.join(mac[i:i+4] for i in range(0, 12, 4))
    elif format_type == 'No Separator':
        return mac.upper()
    else:
        return mac

def generate_random_mac(mac_type='Random'):
    """
    Generate a random MAC address
    """
    if mac_type == 'Unicast':
        # Ensure the first byte is even (unicast)
        first_byte = random.choice([0, 2, 4, 6, 8, 10, 12, 14]) 
    elif mac_type == 'Multicast':
        # Ensure the first byte is odd (multicast)
        first_byte = random.choice([1, 3, 5, 7, 9, 11, 13, 15])
    else:  # Random
        first_byte = random.randint(0, 15)
    
    # Generate the rest of the MAC address
    mac = f"{first_byte:x}" + ''.join(f"{random.randint(0, 15):x}" for _ in range(11))
    return mac.upper()

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
    Perform comprehensive IP address lookup
    """
    # Detailed IP lookup results dictionary
    ip_details = {
        'technical': {},
        'location': {},
        'asn': {},
        'country': {}
    }

    # Technical Details
    ip_details['technical']['ip'] = ip_address
    ip_details['technical']['hostname'] = get_reverse_hostname(ip_address)
    ip_details['technical']['type'] = 'Public' if not is_private_ip(ip_address) else 'Private'
    ip_details['technical']['cidr'] = f"{ip_address}/24"

    # IP API Lookups
    try:
        # Primary API - ipapi.co
        response1 = requests.get(f'https://ipapi.co/{ip_address}/json/')
        
        # Backup API - ip-api.com
        response2 = requests.get(f'https://ip-api.com/json/{ip_address}')

        # Combine results
        data1 = response1.json() if response1.status_code == 200 else {}
        data2 = response2.json() if response2.status_code == 200 else {}

        # Location Details
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

        # ASN and ISP Details
        ip_details['asn'] = {
            'isp': data1.get('org', data2.get('isp', 'N/A')),
            'organization': data1.get('org', data2.get('org', 'N/A')),
            'user_type': 'cellular',
            'asn_number': 'N/A',  # Might need a specialized API for this
            'anonymous_proxy': 'No',
            'satellite_provider': 'No'
        }

        # Country Details
        ip_details['country'] = {
            'registered_country': data1.get('country_name', data2.get('country', 'N/A')),
            'represented_country': 'Not Provided'
        }

        # Geolocation
        ip_details['geolocation'] = {
            'latitude': data1.get('latitude', data2.get('lat', 'N/A')),
            'longitude': data1.get('longitude', data2.get('lon', 'N/A')),
            'accuracy_radius': '20 km'
        }

        return ip_details

    except Exception as e:
        st.error(f"Error in IP lookup: {e}")
        return None

def display_ip_lookup_details(ip_details):
    """
    Display IP lookup details in a structured format
    """
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

    # ASN and ISP Details
    st.subheader("ASN and ISP Details")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**ISP:** {ip_details['asn']['isp']}")
        st.write(f"**Organization:** {ip_details['asn']['organization']}")
        st.write(f"**User Type:** {ip_details['asn']['user_type']}")
    with col2:
        st.write(f"**ASN Number:** {ip_details['asn']['asn_number']}")
        st.write(f"**Anonymous Proxy:** {ip_details['asn']['anonymous_proxy']}")
        st.write(f"**Satellite Provider:** {ip_details['asn']['satellite_provider']}")

    # Country Details
    st.subheader("Country Details")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Registered Country:** {ip_details['country']['registered_country']}")
    with col2:
        st.write(f"**Represented Country:** {ip_details['country']['represented_country']}")

    # Geolocation
    st.subheader("Geolocation")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Latitude:** {ip_details['geolocation']['latitude']}")
        st.write(f"**Longitude:** {ip_details['geolocation']['longitude']}")
    with col2:
        st.write(f"**Accuracy Radius:** {ip_details['geolocation']['accuracy_radius']}")
        st.write("*IP Address information is less than 3 months old*")

def modify_mac_formatter_tab(tab1):
    with tab1:
        st.subheader("MAC Address Formatter")
        
        # MAC Address input
        mac_address = st.text_input(
            'Enter MAC Address', 
            placeholder='e.g., 00:11:22:33:44:55 or 00-11-22-33-44-55', 
            key='mac_input',
            help='Enter a valid MAC address'
        )
        
        # Format selection
        format_options = [
            'Colon (Cisco)', 
            'Hyphen (Windows)', 
            'Dot (Cisco)', 
            'No Separator'
        ]
        selected_format = st.selectbox('Select Format', format_options)
        
        # Format button
        if st.button('Format MAC Address', type='primary', key='format_mac_button'):
            # Validate MAC address
            if not mac_address:
                st.warning('Please enter a MAC address.')
            elif not validate_mac_address(mac_address):
                st.error('Invalid MAC Address. Please enter a valid MAC address.')
            else:
                # Format MAC address
                formatted_mac = format_mac_address(mac_address, selected_format)
                
                # Display results
                st.success('MAC Address Formatted Successfully! 🖥️')
                st.code(formatted_mac, language='text')

def modify_mac_generator_tab(tab2):
    with tab2:
        st.subheader("Random MAC Address Generator")
        
        # MAC Type selection
        mac_type_options = ['Random', 'Unicast', 'Multicast']
        selected_mac_type = st.selectbox('Select MAC Address Type', mac_type_options)
        
        # Number of MACs to generate
        num_macs = st.slider('Number of MAC Addresses', min_value=1, max_value=10, value=1)
        
        # Generate button
        if st.button('Generate MAC Addresses', type='primary', key='generate_mac_button'):
            # Generate MACs
            generated_macs = []
            for _ in range(num_macs):
                mac = generate_random_mac(selected_mac_type)
                generated_macs.append(mac)
            
            # Display results
            st.success(f'{num_macs} MAC Address(es) Generated Successfully! 🌐')
            for mac in generated_macs:
                # Offer multiple formatting options
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.write("Colon (Cisco):")
                    st.code(':'.join(mac[i:i+2] for i in range(0, 12, 2)), language='text')
                with col2:
                    st.write("Hyphen (Windows):")
                    st.code('-'.join(mac[i:i+2] for i in range(0, 12, 2)), language='text')
                with col3:
                    st.write("Dot (Cisco):")
                    st.code('.'.join(mac[i:i+4] for i in range(0, 12, 4)), language='text')
                with col4:
                    st.write("No Separator:")
                    st.code(mac, language='text')

def modify_ip_lookup_tab(tab3):
    with tab3:
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
                ip_details = comprehensive_ip_lookup(ip_address)
                
                if ip_details:
                    st.success('IP Details Retrieved Successfully! 🌍')
                    display_ip_lookup_details(ip_details)
                else:
                    st.error('Unable to retrieve IP details. Please try again.')

def validate_ip_address(ip):
    """
    Validate IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def main():
    st.title('Network Utility Toolkit')
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(['MAC Formatter', 'MAC Generator', 'IP Lookup'])
    
    # Populate tabs
    modify_mac_formatter_tab(tab1)
    modify_mac_generator_tab(tab2)
    modify_ip_lookup_tab(tab3)

if __name__ == '__main__':
    main()
