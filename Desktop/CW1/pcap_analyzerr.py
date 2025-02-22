
import argparse
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import defaultdict
from datetime import datetime
import colorama
from colorama import Fore, Style
import os
import logging
import unittest
from unittest.mock import Mock, patch
import threading
from queue import Queue  
from typing import Dict, List, Set, Optional

class AdvancedPCAPAnalyzer:
    def __init__(self, pcap_file: str):
        """Initialize the PCAP analyzer with thread-safe data structures"""
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
            
        self.pcap_file = pcap_file
        colorama.init()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Thread-safe storage
        self._lock = threading.Lock()
        self.successful_logins = []
        self.suspicious_activities = []
        self.file_transfers = []
        self.unique_suspicious_activities = set()
        
        # Compile patterns
        self.patterns = {
            'ftp_auth': re.compile(rb'USER (.+?)\r?\n'),
            'ftp_pass': re.compile(rb'PASS (.+?)\r?\n'),
            'ftp_success': re.compile(rb'230 '),
            'ftp_file': re.compile(rb'RETR (.+?)\r?\n'),
            'telnet_user': re.compile(rb'(?i)(login|username):\s*(\w+)'),
            'telnet_pass': re.compile(rb'(?i)password:\s*(\w+)'),
            'telnet_success': re.compile(rb'(?i)(login successful|welcome|last login)'),
            'telnet_fail': re.compile(rb'(?i)(login failed|incorrect|invalid)'),
            'suspicious_commands': re.compile(
                rb'(?i)(exec|system|select|union|delete|drop|update|cmd\.exe|/bin/sh|'
                rb'malicious|whoami|curl|wget|nc\s|netcat)'
            )
        }
        
        # Thread-safe pending logins storage
        self.pending_logins = defaultdict(dict)
        self.pending_lock = threading.Lock()
        
        # Protocol mappings
        self.port_to_protocol = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB'
        }

    def _add_login(self, login_data: Dict) -> None:
        """Thread-safe method to add login attempts"""
        with self._lock:
            self.successful_logins.append(login_data)

    def _add_suspicious_activity(self, activity_data: Dict) -> None:
        """Thread-safe method to add suspicious activities"""
        with self._lock:
            activity_tuple = (
                activity_data['type'],
                activity_data['src_ip'],
                activity_data['dst_ip'],
                activity_data['protocol']
            )
            if activity_tuple not in self.unique_suspicious_activities:
                self.unique_suspicious_activities.add(activity_tuple)
                self.suspicious_activities.append(activity_data)

    def _add_file_transfer(self, transfer_data: Dict) -> None:
        """Thread-safe method to add file transfers"""
        with self._lock:
            self.file_transfers.append(transfer_data)

    def _analyze_telnet(self, payload: bytes, packet_num: int, src_ip: str, dst_ip: str) -> None:
        """Analyze Telnet login attempts"""
        with self.pending_lock:
            username_match = self.patterns['telnet_user'].search(payload)
            password_match = self.patterns['telnet_pass'].search(payload)
            success_match = self.patterns['telnet_success'].search(payload)
            fail_match = self.patterns['telnet_fail'].search(payload)

            if username_match:
                username = username_match.group(2).decode('utf-8', 'ignore')
                self.pending_logins[src_ip]['username'] = username
                self.pending_logins[src_ip]['packet_number'] = packet_num

            if password_match and src_ip in self.pending_logins:
                password = password_match.group(1).decode('utf-8', 'ignore')
                self.pending_logins[src_ip]['password'] = password

            if success_match and src_ip in self.pending_logins:
                login_info = self.pending_logins[src_ip]
                if 'username' in login_info and 'password' in login_info:
                    self._add_login({
                        'packet_number': packet_num,
                        'username': login_info['username'],
                        'password': login_info['password'],
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': 'TELNET',
                        'activity': 'Successful Telnet login'
                    })
                del self.pending_logins[src_ip]

            if fail_match and src_ip in self.pending_logins:
                del self.pending_logins[src_ip]

    def _analyze_ftp(self, payload: bytes, packet_num: int, src_ip: str, dst_ip: str) -> None:
        """Analyze FTP login attempts and file transfers"""
        with self.pending_lock:
            username_match = self.patterns['ftp_auth'].search(payload)
            password_match = self.patterns['ftp_pass'].search(payload)
            success_match = self.patterns['ftp_success'].search(payload)
            
            if username_match:
                username = username_match.group(1).decode('utf-8', 'ignore')
                self.pending_logins[src_ip] = {
                    'username': username,
                    'protocol': 'FTP',
                    'status': 'pending'
                }
            
            if password_match and src_ip in self.pending_logins:
                password = password_match.group(1).decode('utf-8', 'ignore')
                self.pending_logins[src_ip]['password'] = password
            
            if success_match and dst_ip in self.pending_logins:
                login_info = self.pending_logins[dst_ip]
                if 'password' in login_info:
                    self._add_login({
                        'packet_number': packet_num,
                        'username': login_info['username'],
                        'password': login_info['password'],
                        'src_ip': dst_ip,
                        'dst_ip': src_ip,
                        'protocol': 'FTP',
                        'activity': 'Successful FTP login'
                    })
                del self.pending_logins[dst_ip]

            file_match = self.patterns['ftp_file'].search(payload)
            if file_match:
                self._add_file_transfer({
                    'packet_number': packet_num,
                    'filename': file_match.group(1).decode('utf-8', 'ignore'),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': 'FTP',
                    'activity': 'File transfer detected'
                })

    def _analyze_packet(self, packet: scapy.packet.Packet, packet_num: int) -> None:
        """Analyze a single packet for suspicious activities and login attempts"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                protocol = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'IP-{proto}')
                
                if TCP in packet and Raw in packet:
                    payload = packet[Raw].load
                    dst_port = packet[TCP].dport
                    src_port = packet[TCP].sport
                    
                    # Analyze based on port
                    if dst_port == 21 or src_port == 21:
                        self._analyze_ftp(payload, packet_num, src_ip, dst_ip)
                    elif dst_port == 23 or src_port == 23:
                        self._analyze_telnet(payload, packet_num, src_ip, dst_ip)
                    
                    # Check for suspicious commands
                    match = self.patterns['suspicious_commands'].search(payload)
                    if match:
                        self._add_suspicious_activity({
                            'packet_number': packet_num,
                            'type': match.group(0).decode('utf-8', 'ignore'),
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'protocol': protocol,
                            'activity': 'Suspicious command detected'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Packet {packet_num} error: {str(e)}")

    def analyze(self, threads: int = 4) -> None:
        """Analyze the PCAP file using multiple threads"""
        print(f"{Fore.CYAN}[*] Starting analysis of {self.pcap_file}...{Style.RESET_ALL}")
        try:
            packets = rdpcap(self.pcap_file)
            total_packets = len(packets)
            
            print(f"{Fore.CYAN}[*] Found {total_packets} packets to analyze{Style.RESET_ALL}")
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(self._analyze_packet, packet, i): i 
                    for i, packet in enumerate(packets, 1)
                }
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    if completed % 1000 == 0:
                        percentage = (completed / total_packets) * 100
                        print(f"Progress: {completed}/{total_packets} packets analyzed ({percentage:.1f}%)")
                    future.result()
                    
            print(f"{Fore.GREEN}[+] Analysis complete!{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing PCAP: {str(e)}{Style.RESET_ALL}")
            raise

    def print_detailed_results(self) -> None:
        """Print detailed analysis results with proper formatting"""
        try:
            # Print suspicious activities
            print(f"\n{Fore.CYAN}=== Suspicious Activities Report ==={Style.RESET_ALL}")
            if self.suspicious_activities:
                for activity in self.suspicious_activities:
                    print(f"{Fore.RED}[!] {activity['activity']} in Packet {activity['packet_number']} "
                          f"({activity['protocol']}): {activity['type']} "
                          f"from {activity['src_ip']} to {activity['dst_ip']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}No suspicious activities detected.{Style.RESET_ALL}")
            
            # Print successful logins by protocol
            print(f"\n{Fore.CYAN}=== Successful Logins Report ==={Style.RESET_ALL}")
            if self.successful_logins:
                logins_by_protocol = defaultdict(list)
                for login in self.successful_logins:
                    logins_by_protocol[login.get('protocol', 'Unknown')].append(login)
                
                for protocol, logins in logins_by_protocol.items():
                    print(f"\n{Fore.YELLOW}[+] {protocol} Logins:{Style.RESET_ALL}")
                    for login in logins:
                        print(f"    Packet: {login['packet_number']}")
                        print(f"    Activity: {login['activity']}")
                        print(f"    Username: {login['username']}")
                        print(f"    Password: {login['password']}")
                        print(f"    From: {login['src_ip']}")
                        print(f"    To: {login['dst_ip']}")
                        print(f"    {'-' * 60}")
            else:
                print(f"{Fore.GREEN}No successful logins detected.{Style.RESET_ALL}")
            
            # Print file transfers
            print(f"\n{Fore.CYAN}=== File Transfers Report ==={Style.RESET_ALL}")
            if self.file_transfers:
                for transfer in self.file_transfers:
                    print(f"{Fore.YELLOW}[+] Transfer Details:{Style.RESET_ALL}")
                    print(f"    Packet: {transfer['packet_number']}")
                    print(f"    Activity: {transfer['activity']}")
                    print(f"    Filename: {transfer['filename']}")
                    print(f"    From: {transfer['src_ip']}")
                    print(f"    To: {transfer['dst_ip']}")
                    print(f"    Protocol: {transfer.get('protocol', 'Unknown')}")
                    print(f"    {'-' * 60}")
            else:
                print(f"{Fore.GREEN}No file transfers detected.{Style.RESET_ALL}")

            # Print analysis summary
            print(f"\n{Fore.CYAN}=== Analysis Summary ==={Style.RESET_ALL}")
            print(f"Total suspicious activities: {len(self.suspicious_activities)}")
            print(f"Total successful logins: {len(self.successful_logins)}")
            print(f"Total file transfers: {len(self.file_transfers)}")

        except Exception as e:
            self.logger.error(f"Error printing results: {str(e)}")
            print(f"{Fore.RED}[!] Error occurred while printing results. Check the logs for details.{Style.RESET_ALL}")

def main():
    """Main entry point for the PCAP analyzer"""
    parser = argparse.ArgumentParser(
        description='Advanced Network Forensic Analyzer',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-t', '--threads', type=int, default=4,
                       help='Number of analysis threads')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    args = parser.parse_args()
    
    try:
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        analyzer = AdvancedPCAPAnalyzer(args.pcap_file)
        analyzer.analyze(threads=args.threads)
        analyzer.print_detailed_results()
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == '__main__':
    exit(main())