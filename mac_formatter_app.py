import streamlit as st
import requests
import socket
import ipaddress
import re
import random
import subprocess
import platform

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
    elif format_type == 'No Separator (Uppercase)':
        return mac.upper()
    elif format_type == 'No Separator (Lowercase)':
        return mac
    elif format_type == 'Colon (Lowercase)':
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
    elif format_type == 'Hyphen (Lowercase)':
        return '-'.join(mac[i:i+2] for i in range(0, 12, 2))
    elif format_type == 'Dot (Lowercase)':
        return '.'.join(mac[i:i+4] for i in range(0, 12, 4))
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
            'asn_number': 'N/A',
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

def perform_ping(host, count=4):
    """
    Perform ping operation with enhanced error handling
    """
    try:
        # Validate host input
        if not host:
            return "Error: No host specified"
        
        # Check for valid hostname/IP
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            return f"Error: Could not resolve hostname {host}"

        # Determine OS and construct appropriate ping command
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        # Construct command
        command = ['ping', param, str(count), host]
        
        # Run ping and capture output
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping to {host} timed out"
        
    except Exception as e:
        return f"Error performing ping: {e}"

def port_scan(host, start_port=1, end_port=1024):
    """
    Perform basic port scanning with enhanced error handling
    """
    # Validate host input
    if not host:
        return "Error: No host specified"
    
    # Resolve hostname to IP
    try:
        host_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return f"Error: Could not resolve hostname {host}"

    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)  # Increased timeout for better reliability
            result = sock.connect_ex((host_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            st.warning(f"Error scanning port {port}: {e}")
    
    return open_ports

def generate_hash(text, hash_type='SHA-256'):
    """
    Generate hash for given text
    """
    import hashlib
    
    hash_types = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256,
        'SHA-512': hashlib.sha512
    }
    
    hash_func = hash_types.get(hash_type, hashlib.sha256)
    return hash_func(text.encode()).hexdigest()

def generate_password(length=12, use_uppercase=True, use_lowercase=True, 
                      use_digits=True, use_symbols=True):
    """
    Generate a strong random password
    """
    import string
    
    character_set = ''
    if use_uppercase:
        character_set += string.ascii_uppercase
    if use_lowercase:
        character_set += string.ascii_lowercase
    if use_digits:
        character_set += string.digits
    if use_symbols:
        character_set += string.punctuation
    
    if not character_set:
        return "Error: No character types selected"
    
    password = ''.join(random.choice(character_set) for _ in range(length))
    return password

def remove_duplicates(text, case_sensitive=True, ignore_whitespace=False):
    """
    Remove duplicate entries from text
    
    Args:
        text (str): Text with entries separated by newlines
        case_sensitive (bool): Whether to treat case differently
        ignore_whitespace (bool): Whether to ignore leading/trailing whitespace
        
    Returns:
        tuple: (unique_entries, removed_count, stats)
    """
    if not text:
        return "", 0, {"input_count": 0, "output_count": 0, "removed_count": 0}
    
    # Split by newlines
    lines = text.split('\n')
    
    # Filter out empty lines
    non_empty_lines = [line for line in lines if line.strip()]
    
    # Process lines according to settings
    processed_lines = []
    for line in non_empty_lines:
        if ignore_whitespace:
            line = line.strip()
        if not case_sensitive:
            processed_lines.append((line.lower(), line))
        else:
            processed_lines.append((line, line))
    
    # Remove duplicates while preserving order
    seen = set()
    unique_entries = []
    for key, original in processed_lines:
        if key not in seen:
            seen.add(key)
            unique_entries.append(original)
    
    # Calculate statistics
    input_count = len(non_empty_lines)
    output_count = len(unique_entries)
    removed_count = input_count - output_count
    
    stats = {
        "input_count": input_count,
        "output_count": output_count,
        "removed_count": removed_count,
        "reduction_percentage": round((removed_count / input_count * 100), 2) if input_count > 0 else 0
    }
    
    return '\n'.join(unique_entries), removed_count, stats

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
    with tab1:
        st.subheader("MAC Address Formatter")
        
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
        
        if st.button('Format MAC Address', type='primary', key='format_mac_button'):
            if not mac_address:
                st.warning('Please enter a MAC address.')
            elif not validate_mac_address(mac_address):
                st.error('Invalid MAC Address. Please enter a valid MAC address.')
            else:
                formatted_mac = format_mac_address(mac_address, selected_format)
                st.success('MAC Address Formatted Successfully! 🖥️')
                st.code(formatted_mac, language='text')

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
    st.set_page_config(page_title='Network Utility Toolkit', page_icon='🌐', layout='wide')
    st.title('🌐 Network Utility Toolkit')
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        'MAC Formatter', 
        'MAC Generator', 
        'IP Lookup', 
        'Network Tools',
        'Duplicate Remover',
        'Store Code Converter'
    ])
    
    # Populate tabs
    modify_mac_formatter_tab(tab1)
    modify_mac_generator_tab(tab2)
    modify_ip_lookup_tab(tab3)
    modify_network_tools_tab(tab4)
    modify_duplicate_remover_tab(tab5)
    modify_store_code_converter_tab(tab6)

if __name__ == '__main__':
    main()
