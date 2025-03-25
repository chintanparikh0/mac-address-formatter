import streamlit as st
import re

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

def main():
    st.set_page_config(page_title="MAC Address Formatter", page_icon="🖥️")
    
    st.title('🌐 MAC Address Formatter')
    st.markdown("Convert your MAC address into multiple formats!")
    
    # Input field for MAC address
    mac_address = st.text_input('Enter MAC Address', 
                                placeholder='00:11:22:33:44:55 or 001122334455', 
                                help='Input MAC address with or without separators')
    
    # Add some informative sidebar
    st.sidebar.header("About MAC Addresses")
    st.sidebar.info("""
    A MAC (Media Access Control) address is a unique identifier assigned to network interfaces.
    - 12 hexadecimal characters
    - Can be separated by colons, hyphens, or dots
    - Uniquely identifies network hardware
    """)
    
    if st.button('Format MAC Address', type='primary'):
        # Validate and format MAC address
        if mac_address:
            formatted_macs = format_mac_address(mac_address)
            
            if formatted_macs:
                st.success('MAC Address Formatted Successfully! 🎉')
                
                # Display formatted MAC addresses in a more visual way
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Formats")
                    for format_name, formatted_mac in formatted_macs.items():
                        st.code(f"{format_name}: {formatted_mac}")
                
                with col2:
                    st.subheader("Quick Copy")
                    for format_name, formatted_mac in formatted_macs.items():
                        if st.button(format_name, key=format_name):
                            st.clipboard(formatted_mac)
            else:
                st.error('Invalid MAC Address. Please enter a 12-character MAC address.')
        else:
            st.warning('Please enter a MAC address.')

if __name__ == '__main__':
    main()
