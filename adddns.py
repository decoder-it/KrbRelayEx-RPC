from ipaddress import IPv4Network, IPv4Address
from colorama import Fore, Style
from uuid import uuid4
import dns.resolver
import dns.update
import dns.query
import dns.rcode
import importlib
import random
import socket
import queue

import argparse
parser = argparse.ArgumentParser(description=" domain, dnip, hostname, and hostip arguments.")

parser.add_argument("--domain", required=True, help="Specify the domain name.")
parser.add_argument("--dnsip", required=True, help="Specify the domain's IP address.")
parser.add_argument("--hostname", required=True, help="Specify the hostname.")
parser.add_argument("--hostip", required=True, help="Specify the host's IP address.")

args = parser.parse_args()

 
domain = args.domain
dnsip = args.dnsip
hostname = args.hostname
hostip = args.hostip
delete = dns.update.Update(domain)
delete.delete(hostname)
response = dns.query.tcp(delete, dnsip, timeout=10)
print(response.rcode())
add = dns.update.Update(domain)
add.add(hostname, 300, "A", hostip)
response = dns.query.tcp(add, dnsip, timeout=10)
print(response.rcode())
