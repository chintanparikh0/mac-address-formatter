#!/usr/bin/env python3
import unittest
from mac_formatter_app import (
    validate_mac_address,
    format_mac_address,
    generate_random_mac,
    validate_ip_address,
    is_private_ip,
    generate_hash,
    generate_password,
    remove_duplicates,
    convert_store_code
)

class TestMACFormatter(unittest.TestCase):
    def test_validate_mac_address(self):
        """Test MAC address validation"""
        # Valid MAC addresses
        self.assertTrue(validate_mac_address('00:11:22:33:44:55'))
        self.assertTrue(validate_mac_address('00-11-22-33-44-55'))
        self.assertTrue(validate_mac_address('001122334455'))
        self.assertTrue(validate_mac_address('00:11:22:33:44:5A'))
        
        # Invalid MAC addresses
        self.assertFalse(validate_mac_address('00:11:22:33:44'))  # Too short
        self.assertFalse(validate_mac_address('00:11:22:33:44:55:66'))  # Too long
        self.assertFalse(validate_mac_address('GG:11:22:33:44:55'))  # Invalid chars
        self.assertFalse(validate_mac_address(''))  # Empty
        self.assertFalse(validate_mac_address('not-a-mac'))  # Invalid format

    def test_format_mac_address(self):
        """Test MAC address formatting"""
        mac = '001122334455'
        self.assertEqual(format_mac_address(mac, 'Colon (Cisco)'), '00:11:22:33:44:55')
        self.assertEqual(format_mac_address(mac, 'Hyphen (Windows)'), '00-11-22-33-44-55')
        self.assertEqual(format_mac_address(mac, 'Dot (Cisco)'), '0011.2233.4455')
        self.assertEqual(format_mac_address(mac, 'No Separator (Uppercase)'), '001122334455')
        self.assertEqual(format_mac_address(mac, 'No Separator (Lowercase)'), '001122334455')

    def test_generate_random_mac(self):
        """Test random MAC address generation"""
        # Test Unicast
        mac = generate_random_mac('Unicast')
        first_byte = int(mac[:2], 16)
        self.assertEqual(first_byte & 0x01, 0)  # Check if least significant bit is 0
        
        # Test Multicast
        mac = generate_random_mac('Multicast')
        first_byte = int(mac[:2], 16)
        self.assertEqual(first_byte & 0x01, 1)  # Check if least significant bit is 1
        
        # Test Random
        mac = generate_random_mac('Random')
        self.assertEqual(len(mac), 12)
        self.assertTrue(all(c in '0123456789ABCDEF' for c in mac))
        
        # Test multiple generations
        macs = [generate_random_mac('Random') for _ in range(10)]
        self.assertEqual(len(set(macs)), 10)  # All should be unique

class TestIPTools(unittest.TestCase):
    def test_validate_ip_address(self):
        """Test IP address validation"""
        self.assertTrue(validate_ip_address('192.168.1.1'))
        self.assertTrue(validate_ip_address('8.8.8.8'))
        self.assertFalse(validate_ip_address('256.256.256.256'))
        self.assertFalse(validate_ip_address('not-an-ip'))

    def test_is_private_ip(self):
        """Test private IP detection"""
        self.assertTrue(is_private_ip('192.168.1.1'))
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertFalse(is_private_ip('8.8.8.8'))

class TestCryptoTools(unittest.TestCase):
    def test_generate_hash(self):
        """Test hash generation"""
        text = "test"
        # Test different hash types
        self.assertEqual(len(generate_hash(text, 'MD5')), 32)
        self.assertEqual(len(generate_hash(text, 'SHA-1')), 40)
        self.assertEqual(len(generate_hash(text, 'SHA-256')), 64)
        self.assertEqual(len(generate_hash(text, 'SHA-512')), 128)

    def test_generate_password(self):
        """Test password generation"""
        # Test length
        password = generate_password(length=12)
        self.assertEqual(len(password), 12)
        
        # Test character types
        password = generate_password(
            length=20,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True
        )
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(not c.isalnum() for c in password))

class TestUtilityTools(unittest.TestCase):
    def test_remove_duplicates(self):
        """Test duplicate removal"""
        text = "apple\nAPPLE\nbanana\nbanana\n  cherry  \ncherry"
        
        # Test case sensitive
        result, count, stats = remove_duplicates(text, case_sensitive=True, ignore_whitespace=True)
        self.assertEqual(len(result.split('\n')), 4)  # apple, APPLE, banana, cherry
        
        # Test case insensitive
        result, count, stats = remove_duplicates(text, case_sensitive=False, ignore_whitespace=True)
        self.assertEqual(len(result.split('\n')), 3)  # apple/APPLE counts as one, banana, cherry
        
        # Test with whitespace
        text_with_spaces = "  test  \ntest\n  test  "
        result, count, stats = remove_duplicates(text_with_spaces, ignore_whitespace=True)
        self.assertEqual(len(result.split('\n')), 1)  # All 'test' entries should be considered duplicates
        
        # Test empty input
        result, count, stats = remove_duplicates("")
        self.assertEqual(result, "")
        self.assertEqual(count, 0)
        self.assertEqual(stats["input_count"], 0)
        
        # Test stats
        result, count, stats = remove_duplicates("a\na\nb\nc\nc")
        self.assertEqual(stats["input_count"], 5)
        self.assertEqual(stats["output_count"], 3)
        self.assertEqual(stats["removed_count"], 2)
        self.assertEqual(stats["reduction_percentage"], 40.0)

    def test_convert_store_code(self):
        """Test store code conversion"""
        self.assertEqual(convert_store_code('A147'), '10147')
        self.assertEqual(convert_store_code('B220'), '11220')
        self.assertEqual(convert_store_code('Z999'), '35999')
        self.assertEqual(convert_store_code('147'), '147')  # No letter prefix

if __name__ == '__main__':
    unittest.main() 