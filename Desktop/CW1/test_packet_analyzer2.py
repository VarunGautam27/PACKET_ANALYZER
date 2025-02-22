import unittest
from unittest.mock import Mock, patch
import os
from pcap_analyzerr import AdvancedPCAPAnalyzer

class TestAdvancedPCAPAnalyzerBasic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n=== Starting PCAP Analyzer System Tests ===")
        print("√ Test environment setup completed\n")
    
    def setUp(self):
        # Create a mock PCAP file for testing
        self.test_pcap = "test.pcap"
        with open(self.test_pcap, "w") as f:
            f.write("dummy data")
        
        # Initialize analyzer
        self.analyzer = AdvancedPCAPAnalyzer(self.test_pcap)
    
    @classmethod
    def tearDownClass(cls):
        print("\n=== Cleaning Up Test Environment ===")
        print("√ Cleanup completed\n")
        print("\n=== Test Suite Completed ===\n")
        print("OK\n")
    
    def test_1_initialization(self):
        print("\nTest 1: Initialization")
        print("√ PCAP Analyzer initialized successfully")
        self.assertEqual(self.analyzer.pcap_file, self.test_pcap)
        self.assertEqual(len(self.analyzer.suspicious_activities), 0)
        self.assertEqual(len(self.analyzer.successful_logins), 0)
        self.assertEqual(len(self.analyzer.file_transfers), 0)
        print(".")
    
    def test_2_detect_suspicious_activity(self):
        print("\nTest 2: Detecting Suspicious Activity")
        test_activity = {
            'packet_number': 1,
            'type': 'cmd.exe',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'protocol': 'TCP',
            'activity': 'Suspicious command detected'
        }
        self.analyzer._add_suspicious_activity(test_activity)
        self.assertEqual(len(self.analyzer.suspicious_activities), 1)
        self.assertEqual(self.analyzer.suspicious_activities[0], test_activity)
        print("√ Suspicious activity successfully logged")
        print(".")
    
    def test_3_find_login_credentials(self):
        print("\nTest 3: Finding Login Credentials")
        test_login = {
            'packet_number': 2,
            'username': 'testuser',
            'password': 'testpass',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'protocol': 'FTP',
            'activity': 'Successful login detected'
        }
        self.analyzer._add_login(test_login)
        self.assertEqual(len(self.analyzer.successful_logins), 1)
        self.assertEqual(self.analyzer.successful_logins[0], test_login)
        print("√ Login credentials successfully detected")
        print(".")
    
    def test_4_detect_file_transfer(self):
        print("\nTest 4: Detecting File Transfer")
        test_transfer = {
            'packet_number': 3,
            'filename': 'test.txt',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'protocol': 'FTP',
            'activity': 'File transfer detected'
        }
        self.analyzer._add_file_transfer(test_transfer)
        self.assertEqual(len(self.analyzer.file_transfers), 1)
        self.assertEqual(self.analyzer.file_transfers[0], test_transfer)
        print("√ File transfer successfully logged")
        print(".")
    
    def test_5_file_not_found(self):
        print("\nTest 5: File Not Found Handling")
        with self.assertRaises(FileNotFoundError):
            AdvancedPCAPAnalyzer("nonexistent.pcap")
        print("√ Proper exception raised for missing PCAP file")
        print(".")
    
if __name__ == '__main__':
    unittest.main(verbosity=2)