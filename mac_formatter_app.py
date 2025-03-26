import streamlit as st
import re
import random

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

def main():
    st.set_page_config(page_title="MAC Address Formatter", page_icon="🖥️")
    
    st.title('🌐 MAC Address Formatter')
    st.markdown("Convert your MAC address into multiple formats!")
    
    # Create tabs for different functionalities
    tab1, tab2 = st.tabs(["Format MAC Address", "Generate Random MAC"])
    
    with tab1:
        # Input field for MAC address
        mac_address = st.text_input('Enter MAC Address', 
                                    placeholder='00:11:22:33:44:55 or 001122334455', 
                                    key='format_input',
                                    help='Input MAC address with or without separators')
        
        if st.button('Format MAC Address', type='primary', key='format_button'):
            # Validate and format MAC address
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
        st.subheader("Generate Random MAC Address")
        
        # MAC Address Type Selection
        mac_type = st.selectbox(
            "Select MAC Address Type",
            ["Universal (Unicast)", "Locally Administered", "Multicast"],
            help="Choose the type of MAC address to generate"
        )
        
        # Map user-friendly names to internal type names
        type_mapping = {
            "Universal (Unicast)": "universal",
            "Locally Administered": "local", 
            "Multicast": "multicast"
        }
        
        # Generate button
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
    
    # Add some informative sidebar
    st.sidebar.header("About MAC Addresses")
    st.sidebar.info("""
    A MAC (Media Access Control) address is a unique identifier assigned to network interfaces.
    - 12 hexadecimal characters
    - Can be separated by colons, hyphens, or dots
    - Uniquely identifies network hardware
    
    Random MAC Generation Types:
    - Universal: Globally unique unicast address
    - Locally Administered: Locally assigned unique address
    - Multicast: Multicast group address
    """)

if __name__ == '__main__':
    main()
