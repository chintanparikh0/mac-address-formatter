import streamlit as st

def format_mac_address(mac_address):
    length = len(mac_address)

    # Remove any existing separators
    mac_address = mac_address.replace(':', '').replace('-', '')

    if length in [12, 13]:
        # Lowercase formatting
        lower_ip = mac_address.lower()
        hex1 = lower_ip[0:2]
        hex2 = lower_ip[2:4]
        hex3 = lower_ip[4:6]
        hex4 = lower_ip[6:8]
        hex5 = lower_ip[8:10]
        hex6 = lower_ip[10:12]

        # Uppercase formatting
        upper_ip = mac_address.upper()
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
            'Uppercase Format': f"{hexa}{hexb}{hexc}{hexd}{hexe}{hexf}"
        }
    else:
        return None

def main():
    st.title('MAC Address Formatter')
    
    # Input field for MAC address
    mac_address = st.text_input('Enter MAC Address', placeholder='00:11:22:33:44:55 or 001122334455')
    
    if st.button('Format MAC Address'):
        # Validate and format MAC address
        if mac_address:
            formatted_macs = format_mac_address(mac_address)
            
            if formatted_macs:
                st.success('MAC Address Formatted Successfully!')
                
                # Display formatted MAC addresses
                for format_name, formatted_mac in formatted_macs.items():
                    st.code(f"{format_name}: {formatted_mac}")
            else:
                st.error('Invalid MAC Address. Please enter a 12-character MAC address.')
        else:
            st.warning('Please enter a MAC address.')

if __name__ == '__main__':
    main()