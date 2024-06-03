#!/usr/bin/env python3

import concurrent.futures
import datetime
import os
from scapy.all import TCP, ICMP, IP, sr1, RandShort
import sys

## LOGGING
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('LOG_FILE','hosts.log')

def severity_to_int(severity) -> int:
    severities = {"DEBUG": 1,
                  "INFO": 2,
                  "WARNING": 3,
                  "ERROR": 4,
                  "CRITICAL": 5}
    return severities.get(severity.upper(), 0)
    
def logmsg(severity : str, message : str, outfile : str):
     with open(outfile, 'a') as f:
         f.write('{};{}; {}\n'.format(time_now(), severity.upper(), message))

def log(severity: str, message: str):
    if severity_to_int(severity) >= severity_to_int(LOG_LEVEL):
        logmsg(severity.upper(), str(message), LOG_FILE)

def time_now():
    # Example: 2024-06-03 05:44:26 UTC
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S %Z")

## APPLICATION
def ping_host(ip):
    packet = IP(dst=ip, ttl=(64))/ICMP()
    reply = sr1(packet, timeout=0.5, verbose=0)
    if reply is not None:
        log("info",  f"{str(ip)} is up")
        return True
    else:
        return False

def pingsweep(ip) -> list:
    active_hosts = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures_to_ips = {executor.submit(ping_host, f"{ip}.{str(i)}"): f"{ip}.{str(i)}" for i in range(0,254)}

        futures = list(futures_to_ips.keys())
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                active_hosts.append(futures_to_ips[future])
    print("Total hosts up:", len(active_hosts))
    return active_hosts

def tcp_check(ip, port):
    # Create a TCP SYN packet to the target IP and port
    packet = IP(dst=str(ip))/TCP(dport=port, flags="S", seq=RandShort())
    # Send the packet and receive any response
    reply = sr1(packet, timeout=1, verbose=0)
    if reply is not None:
        if reply.haslayer(TCP):
            if reply[TCP].flags & 0x12 == 0x12: # Check for SYN/ACK flags
                log('info', f"{str(ip)}:{port}/tcp is open")
                return True
    return False

## MAIN
def main():
    if len(sys.argv) != 2:
        print("Usage: python pingsweep.py <IP>")
        sys.exit(1)
    ip = sys.argv[1]
    try:
        log('info', 'Starting scan now')
        active_hosts = pingsweep(ip)
        ports = [ 80, 443 ]
        if active_hosts:
            log('info', f'Performing tcp scan for ports {ports}')
            for host in active_hosts:
                for port in ports:
                    tcp_check(host, port)
    except KeyboardInterrupt:
        log('info', 'Scan interrupted by user')
    finally:
        log('info', 'Scan finished')


if __name__ == '__main__':
    main()
