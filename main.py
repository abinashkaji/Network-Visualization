#!/usr/bin/python
# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import matplotlib.plot as plt
from collections import defaultdict, Counter
import pyshark
from scapy.all import *
from __future__ import print_function
import argparse
from collections import Counter
import io
import re
try:
    dict.iteritems
except AttributeError:
    # Python 3
    def iteritems(d):
        """Define iteritems for Python 3."""
        return iter(d.items())
else:
    # Python 2
    def iteritems(d):
        return d.iteritems()

class InvalidSegment(Exception):

NGINX_ACCESS_LOG_REGEX = re.compile(
    r'(?P<ip_address>.*?)\ \-\ (?P<remote_user>.*?)\ \[(?P<time_local>.*?)'
    r'\]\ \"(?P<request>.*?)\"\ (?P<status_code>.*?)\ '
    r'(?P<body_bytes_sent>.*?)\ \"(?P<http_referrer>.*?)\"\ '
    '\"(?P<http_user_agent>.*?)\"',
    re.IGNORECASE
)

ACCESS_LOG_SEGMENT_VERBOSE_MAPPING = {
    'ip_address': {
        'verbose': 'IP Address',
        'verbose_plural': 'IP Addresses'
    },
    'remote_user': {
        'verbose': 'Remote User',
        'verbose_plural': 'Remote Users',
    },
    'status_code': {
        'verbose': 'Status Code',
        'verbose_plural': 'Status Codes',
    },
    'http_referrer': {
        'verbose': 'Referrer',
        'verbose_plural': 'Referrers',
    },
    'http_user_agent': {
        'verbose': 'User Agent',
        'verbose_plural': 'User Agents',
    }
}

ALLOWED_CHOICES_STR = "Allowed choices: {}.".format(
    ', '.join([
        "{} ({})".format(key, value['verbose'])
        for key, value in iteritems(ACCESS_LOG_SEGMENT_VERBOSE_MAPPING)
    ])
)


def count_nginx_log_frequency(log_file_path,
                              regex_group_key,
                              per_line_regex):
    """
    Tally the appearance of values in a nginx log file.

    Args:
        log_file_path (str): The path on disc of the nginx log file to process.
        regex_group_key (str): The named group of `per_line_regex` to count.
        per_line_regex (str): The regex used to parse each line of
            `log_file_path`.

    Returns:
        A collections.Counter instance.

    Raises:
        IOError: If `log_file_path` points to a non-existant file.
        ValueError: If `regex_group_key` cannot be found on a line of
        `log_file_path` with `per_line_regex`.
    """
    with io.open(log_file_path, 'r') as log_file:
        c = Counter([
            per_line_regex.match(line).group(regex_group_key)
            for line in log_file
        ])
    return c


def create_parser():
    """Create a command line parser for this module."""
    parser = argparse.ArgumentParser(
        description='Determine the most frequently logged values from a '
                    'standard nginx access log.'
    )
    parser.add_argument(
        '-s',
        '--segment',
        type=str,
        default='ip_address',
        help="The data segment whose frequency you'd like to determine. "
             "{}".format(ALLOWED_CHOICES_STR)
    )
    parser.add_argument(
        '-l',
        '--limit',
        type=int,
        default=10,
        help='The limit of most-frequently-logged IPs to list. Defaults to 10.'
    )
    parser.add_argument(
        '-f',
        '--file',
        type=str,
        default='/var/log/nginx/access.log',
        help="The path on disk of the nginx access log you'd like evaluated. "
             "Defaults to /var/log/nginx/access.log"
    )
    return parser


def print_report(counter_instance,
                 regex_group_key,
                 top_list_length,
                 log_file_path):
    """
    Print a summary of the tally operation to the shell.

    Args:
        counter_instance (instance): A collections.Counter instance.
        regex_group_key (str): The key for the verbose mapping in
        ACCESS_LOG_SEGMENT_VERBOSE_MAPPING to use for the title section.
        top_list_length (int): The length of the 'top' list you'd like printed.
        log_file_path (str): The path to the proceseed log file for inclusion
        in the title section.

    Returns: None
    """
    if top_list_length > 1:
        verbose_key = 'verbose_plural'
    else:
        verbose_key = 'verbose'

    table_header = (
        "Top {limit} Most Frequently Logged {segment_verbose_plural}".format(
            limit=top_list_length,
            segment_verbose_plural=ACCESS_LOG_SEGMENT_VERBOSE_MAPPING[
                regex_group_key
            ][verbose_key]
        )
    )
    table_header_log = 'According to file: {}'.format(log_file_path)
    header_len = max(
        len(table_header),
        len(table_header_log)
    )
    header_separator = ''.ljust(header_len, '=')
    print(header_separator)
    print(table_header.center(header_len))
    print(table_header_log.center(header_len))
    print(header_separator)
    for num, payload in enumerate(
        counter_instance.most_common(n=top_list_length), start=1
    ):
        ip, count = payload
        print(
            "{num}. {ip}: {count}".format(
                num=str(num).rjust(2),
                ip=ip.ljust(16),
                count=count
            )
        )

if __name__ == '__main__':  # pragma: no cover
    parser = create_parser()

    # Arguments to set
    args = parser.parse_args()
    log_file_path = args.file
    top_list_limit = args.limit
    regex_group_key = args.segment

    if regex_group_key not in ACCESS_LOG_SEGMENT_VERBOSE_MAPPING.keys():
        raise InvalidSegment(
            "'{}' is an invalid data segment type. {}".format(
                regex_group_key,
                ALLOWED_CHOICES_STR
            )
        )

    c = count_nginx_log_frequency(
        log_file_path,
        regex_group_key,
        NGINX_ACCESS_LOG_REGEX
    )
    print_report(c, regex_group_key, top_list_limit, log_file_path)


def get_user_input():
    file_path = input("Please enter the path to the .pcap or .pcapng file: ")
    return file_path

def get_statistics(capture): ' returns count of different protocols and ip used and packet for each protocol and host'
  df=pd.read(, sep='|', cols=['host_ip','dest_ip','protocol'])
  table_packet=df.pivot(row='host_ip')
  'table_proto=df.'
return None
  pass
def visualize(packet_df):     'visualization of given dataframe bar and pie chart'
  plt.pie(packet_df[1,:])
  plt.hist(packet_df[0,:])

def get_all_ip_addresses(capture):
    ip_addresses = set()
    for packet in capture:
        if hasattr(packet, 'IP'):
            ip_addresses.add(packet['IP'].src)
            ip_addresses.add(packet['IP'].dst)
    return ip_addresses

def detect_dns_tunneling(packet):
    if hasattr(packet, 'DNS') and packet.DNS.qr == 0:
        for i in range(packet[DNS].ancount):
            if packet[DNS].an[i].type == 16 and len(packet[DNS].an[i].rdata) > 100:
                print(f"[+] Suspicious activity detected: DNS Tunneling")
                print(packet)

def detect_ssh_tunneling(packet):
    if hasattr(packet, 'SSH') and hasattr(packet, 'TCP') and (packet['TCP'].sport > 1024 or packet['TCP'].dport > 1024):
        print(f"[+] Suspicious activity detected: SSH Tunneling")
        print(packet)

def detect_tcp_session_hijacking(packet):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'FA' and int(packet['TCP'].seq) > 0 and int(packet['TCP'].ack) > 0:
        print(f"[+] Suspicious activity detected: TCP Session Hijacking")
        print(packet)

def detect_smb_attack(packet):
    if hasattr(packet, 'SMB2') and packet['SMB2'].command == 5:
        print(f"[+] Suspicious activity detected: SMB Attack")
        print(packet)

def detect_smtp_dns_attack(packet):
    if (hasattr(packet, 'SMTP') and packet['SMTP'].command == 'HELO') or (hasattr(packet, 'DNS') and packet['DNS'].opcode == 2):
        print(f"[+] Suspicious activity detected: SMTP or DNS Attack")
        print(packet)

def detect_ipv6_fragmentation_attack(packet):
    if hasattr(packet, 'IPv6') and hasattr(packet, 'IPv6ExtHdrFragment') and int(packet['IPv6ExtHdrFragment'].plen) > 1500:
        print(f"[+] Suspicious activity detected: IPv6 Fragmentation Attack")
        print(packet)

def detect_tcp_rst_attack(packet):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'R' and int(packet['TCP'].window) == 0:
        print(f"[+] Suspicious activity detected: TCP RST Attack")
        print(packet)

def detect_syn_flood_attack(packet, syn_counter):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'S' and int(packet['TCP'].window) > 0:
        syn_counter[packet['IP'].src] += 1
        if syn_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
            print(f"[+] Suspicious activity detected: SYN Flood Attack")
            print(packet)

def detect_udp_flood_attack(packet):
    if hasattr(packet, 'UDP') and int(packet['UDP'].len) > 1024:
        print(f"[+] Suspicious activity detected: UDP Flood Attack")
        print(packet)

def detect_slowloris_attack(packet, slowloris_counter):
    if hasattr(packet, 'TCP') and packet['TCP'].flags == 'PA' and int(packet['TCP'].window) > 0 and int(packet['TCP'].len) < 10:
        slowloris_counter[packet['IP'].src] += 1
        if slowloris_counter[packet['IP'].src] > 100:  # Adjust the threshold as needed
            print(f"[+] Suspicious activity detected: Slowloris Attack")
            print(packet)

def main():
    file_path = get_user_input()
    capture = pyshark.FileCapture(file_path, keep_packets=False)
    ip_addresses = get_all_ip_addresses(capture)

    syn_counter = defaultdict(int)
    slowloris_counter = defaultdict(int)
    packet_df=get_statistics(capture) ' returns count of different protocols and ip used and packet for each protocol and host' 
    visualize(packet_df)     'visualization of given dataframe bar and pie chart'

    for source_ip in ip_addresses:
        print(f"\n[+] Checking for IP address {source_ip}")
        capture.reset()
        for packet in capture:
            if hasattr(packet, 'IP') and packet['IP'].src == source_ip:
                detect_dns_tunneling(packet)
                detect_ssh_tunneling(packet)
                detect_tcp_session_hijacking(packet)
                detect_smb_attack(packet)
                detect_smtp_dns_attack(packet)
                detect_ipv6_fragmentation_attack(packet)
                detect_tcp_rst_attack(packet)
                detect_syn_flood_attack(packet, syn_counter)
                detect_udp_flood_attack(packet)
                detect_slowloris_attack(packet, slowloris_counter)

if __name__ == "__main__":
    main()
