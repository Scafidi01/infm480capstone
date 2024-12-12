import scapy.all as scapy
import re

ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")

while True:
    ip_add_range_entered = input("\nPlease enter the ip address and range that you want to scan")