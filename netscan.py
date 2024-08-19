#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, ICMP, IP, sr
import ipaddress
import nmap
from colorama import Fore, Back
import socket
import sys
import argparse
import requests
from os import system
import simpleaudio as sa
import numpy as np
import time

system('clear')
final_start_time = time.time()

def play_tone(frequency=440, duration=0.1, sample_rate=44100):
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    samples = 0.5 * np.sin(2 * np.pi * frequency * t)
    samples = (samples * 32767).astype(np.int16)
    audio = sa.play_buffer(samples, 1, 2, sample_rate)
    audio.wait_done()

def get_mac_vendor(mac_address):
    mac_address = mac_address.upper().replace(":", "").replace("-", "")
    if len(mac_address) != 12 or not all(c in '0123456789ABCDEF' for c in mac_address):
        return "Invalid MAC address format"
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except requests.RequestException:
        return "Unknown Vendor"

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Hostname"

def scan_network(network):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ipaddress.IPv4Network(network)))
    arp_result = srp(packet, timeout=10, verbose=0)[0]

    arp_ips = [{'ip': received.psrc, 'mac': received.hwsrc} for _, received in arp_result]
    arp_ips_set = set(item['ip'] for item in arp_ips)

    nm = nmap.PortScanner()
    nmap_result = nm.scan(hosts=str(network), arguments='-sn')
    
    nmap_ips = [{'ip': host, 'mac': nmap_result['scan'][host]['addresses'].get('mac', 'Unknown')}
                for host in nmap_result['scan']]
    
    combined_ips = {item['ip']: item for item in arp_ips}
    for item in nmap_ips:
        if item['ip'] not in combined_ips:
            combined_ips[item['ip']] = item
        elif combined_ips[item['ip']]['mac'] == 'Unknown':
            combined_ips[item['ip']]['mac'] = item['mac']
    
    return list(combined_ips.values())

def perform_scans(ip):
    play_tone(duration=0.1)
    scan_results = {
        'traceroute': [],
        'tcp_ports': [],
        'udp_ports': [],
        'os_info': [],
        'services': {},
        'vulnerabilities': [],
        'firewall_detection': {}
    }
    
    partial_results = {key: [] if key != 'services' else {} for key in scan_results}
    
    try:
        nm = nmap.PortScanner()
        print(Back.LIGHTBLUE_EX + Fore.WHITE + f'Scanning {ip}' + Back.RESET + Fore.LIGHTBLUE_EX)
        total_start_time = time.time()
        
        # Traceroute
        start_time = time.time()
        print(Fore.LIGHTBLUE_EX + 'Traceroute ' + Fore.CYAN + '@ ' + Fore.YELLOW + str(ip) + Fore.LIGHTBLUE_EX + '...', end="", flush=True)
        
        try:
            ans, _ = sr(IP(dst=ip)/ICMP(), timeout=5, verbose=0)
            traceroute_result = [rcv.src for _, rcv in ans]
            scan_results['traceroute'] = traceroute_result
            partial_results['traceroute'] = traceroute_result
            elapsed_time = time.time() - start_time
            print(Fore.LIGHTGREEN_EX + "\u2713" + Fore.LIGHTBLUE_EX + ' (' + Fore.MAGENTA + f'{elapsed_time:.2f}s' + Fore.LIGHTBLUE_EX + ')')
        except Exception as e:
            print(Fore.WHITE + Back.RED + f'Error during Traceroute: {e}' + Fore.LIGHTBLUE_EX + Back.RESET + '\n\n')
            scan_results['traceroute'] = []
            partial_results['traceroute'] = []
        
        # Scans
        scan_types = [
            ('-T4 -Pn -sS -p "*" --reason', 'TCP Port Scan', 'tcp_ports', 'tcp'),
            ('-T4 -Pn --max-retries 1 -sU --reason', 'UDP Port Scan', 'udp_ports', 'udp'),
            ('-T4 -Pn -O', 'OS Detection Scan', 'os_info', 'osmatch'),
            ('-T4 -Pn -sV', 'Service Version Scan', 'services', 'tcp'),
            ('-T4 -sV --script vulners', 'Vulnerability Scan', 'vulnerabilities', 'tcp'),
            ('-T4 -Pn -sA', 'Firewall Detection Scan', 'firewall_detection', 'tcp')
        ]

        for args, label, result_key, nmap_key in scan_types:
            start_time = time.time()
            print(Fore.LIGHTBLUE_EX + f'{label} ' + Fore.CYAN + '@ ' + Fore.YELLOW + str(ip) + Fore.LIGHTBLUE_EX + '...', end="", flush=True)
            
            try:
                nm.scan(ip, arguments=args)
                data = nm[ip]
                if nmap_key in data:
                    if result_key in ['tcp_ports', 'udp_ports', 'firewall_detection']:
                        for port, details in data[nmap_key].items():
                            scan_results[result_key].append({
                                'port': port, 
                                'state': details['state'], 
                                'service': details.get('name'), 
                                'version': details.get('version'), 
                                'reason': details.get('reason', 'N/A')
                            })
                            partial_results[result_key].append(scan_results[result_key][-1])
                    elif result_key == 'vulnerabilities':
                        for port, details in data[nmap_key].items():
                            if 'script' in details and 'vulners' in details['script']:
                                vulns = details['script']['vulners'].strip()
                                if vulns:
                                    scan_results[result_key].append(vulns)
                                    partial_results[result_key].append(vulns)
                    else:
                        scan_results[result_key] = data[nmap_key]
                        partial_results[result_key] = data[nmap_key]
                elapsed_time = time.time() - start_time
                print(Fore.LIGHTGREEN_EX + "\u2713" + Fore.LIGHTBLUE_EX + ' (' + Fore.MAGENTA + f'{elapsed_time:.2f}s' + Fore.LIGHTBLUE_EX + ')' + Fore.RESET)
            except Exception as e:
                print(Fore.WHITE + Back.RED + f'Error during {label}: {e}' + Fore.LIGHTBLUE_EX + Back.RESET + '\n\n')
                break
        
        total_elapsed_time = time.time() - total_start_time
        return scan_results, total_elapsed_time
    except Exception as e:
        print(Fore.WHITE + Back.RED + f'Error: {str(e)} - Host {ip} Unreachable (Skipping)...' + Fore.LIGHTBLUE_EX + Back.RESET + '\n\n')
        print_scan_results(ip, partial_results, 0)
        return partial_results, 0


def print_scan_results(ip, scan_results, total_time):
    hostname = resolve_hostname(ip)
    print(Fore.LIGHTGREEN_EX + '+' * 40 + Fore.LIGHTBLUE_EX)
    if hostname == 'Unknown Hostname':
        print(Fore.LIGHTBLUE_EX + 'Results for ' + Fore.YELLOW + str(ip) + Fore.RED + ' (' + str(hostname) + ') ' + Fore.LIGHTBLUE_EX + ' (' + Fore.MAGENTA + f'{total_time:.2f}s' + Fore.LIGHTBLUE_EX + ')' + Fore.RESET)
    else:
        print(Fore.LIGHTBLUE_EX + 'Results for ' + Fore.YELLOW + str(ip) + Fore.LIGHTGREEN_EX + ' (' + str(hostname) + ')' + Fore.LIGHTBLUE_EX)
    
    # Traceroute
    print(Fore.CYAN + '-Traceroute:' + Fore.LIGHTBLUE_EX)
    if scan_results['traceroute']:
        for hop in scan_results['traceroute']:
            print(Fore.YELLOW + str(hop) + Fore.LIGHTBLUE_EX)
    else:
        print(Fore.LIGHTRED_EX + 'No traceroute information found.' + Fore.LIGHTBLUE_EX)
    
    # TCP Ports
    print(Fore.CYAN + '-TCP Ports:' + Fore.LIGHTBLUE_EX)
    for port_info in scan_results['tcp_ports']:
        status_label = "open" if port_info['state'] == "open" else "filtered"
        service_info = f'{port_info["service"]} ({port_info["version"]})' if port_info["service"] and port_info["version"] else ''
        if port_info['state'] == "open":
            print(Fore.YELLOW + str(port_info['port']) + ' ' + Fore.LIGHTGREEN_EX + f'({status_label})' + ' ' + Fore.MAGENTA + str(port_info['reason']) + Fore.LIGHTBLUE_EX)
        else:
            print(Fore.YELLOW + str(port_info['port']) + ' ' + Fore.LIGHTYELLOW_EX + f'({status_label})' + ' ' + Fore.MAGENTA + str(port_info['reason']) + Fore.LIGHTBLUE_EX)
    
    # UDP Ports
    print(Fore.CYAN + '-UDP Ports:' + Fore.LIGHTBLUE_EX)
    for port_info in scan_results['udp_ports']:
        status_label = "open" if port_info['state'] == "open" else "filtered"
        if port_info['state'] == "open":
            print(Fore.YELLOW + str(port_info['port']) + ' ' + Fore.LIGHTGREEN_EX + f'({status_label})' + ' ' + Fore.MAGENTA + str(port_info['reason']) + Fore.LIGHTBLUE_EX)
        else:
            print(Fore.YELLOW + str(port_info['port']) + ' ' + Fore.LIGHTYELLOW_EX + f'({status_label})' + ' ' + Fore.MAGENTA + str(port_info['reason']) + Fore.LIGHTBLUE_EX)
    
    # Services
    print(Fore.CYAN + '-Services:' + Fore.LIGHTBLUE_EX)
    for port, service in scan_results['services'].items():
        print(Fore.YELLOW + str(port) + ': ' + Fore.LIGHTGREEN_EX + str(service["name"]) + Fore.CYAN + ' (' + str(service["product"]) + ')' + Fore.LIGHTBLUE_EX)
    
    # OS Information
    print(Fore.CYAN + '-OS Information:' + Fore.LIGHTBLUE_EX)
    if scan_results['os_info']:
        for os in scan_results['os_info']:
            print(Fore.YELLOW + str(os['name']) + Fore.LIGHTGREEN_EX + ' ' + str(os['accuracy']) + '%' + ' ' + Fore.YELLOW + 'accuracy' + Fore.LIGHTBLUE_EX)
    else:
        print(Fore.LIGHTRED_EX + 'No OS information found.' + Fore.LIGHTBLUE_EX)
    
    # Vulnerabilities
    print(Fore.CYAN + '-Vulnerabilities:' + Fore.LIGHTBLUE_EX)
    if scan_results['vulnerabilities']:
        for vuln in scan_results['vulnerabilities']:
            print(Fore.YELLOW + str(vuln) + Fore.LIGHTBLUE_EX)
    else:
        print(Fore.LIGHTRED_EX + 'No vulnerabilities found.' + Fore.LIGHTBLUE_EX)

    # Firewall Detection
    print(Fore.CYAN + '-Firewall Detection:' + Fore.LIGHTBLUE_EX)
    if scan_results['firewall_detection']:
        for fw_info in scan_results['firewall_detection']:
            print(Fore.YELLOW + f"Port {fw_info['port']}: " + Fore.LIGHTGREEN_EX + f"State: {fw_info['state']}, Service: {fw_info['service']}, Version: {fw_info['version']}, Reason: {fw_info.get('reason', 'N/A')}" + Fore.LIGHTBLUE_EX)
    else:
        print(Fore.LIGHTRED_EX + 'No firewall detected or open/filtered state not determined.\n\n' + Fore.LIGHTBLUE_EX)

def main():
    global args
    parser = argparse.ArgumentParser(description='Network Scanner Script')
    parser.add_argument('target', nargs='?', help='Target IP address, network, or website (e.g., 192.168.1.4, 192.168.1.0/24, or example.com)')
    parser.add_argument('-f', '--file', type=str, help='File containing IP addresses to scan')
    parser.add_argument('-sound', action='store_true', help='Play sounds during execution')
    
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r') as f:
                ips = [line.strip() for line in f]
        except FileNotFoundError:
            print(Fore.RED + f'Error: File {args.file} not found.' + Fore.LIGHTBLUE_EX)
            sys.exit(1)
        
        print(Fore.LIGHTBLUE_EX + 'Imported IPs from ' + Fore.YELLOW + args.file + Fore.LIGHTBLUE_EX + '\n')
        for ip in ips:
            print(Fore.YELLOW + str(ip) + Fore.LIGHTBLUE_EX)
        print('\n')

        for ip in ips:
            if not ip.count('.') == 3:
                print(Fore.LIGHTBLUE_EX + f'Resolving website {ip} to IP...' + Fore.LIGHTBLUE_EX)
                try:
                    ip = socket.gethostbyname(ip)
                    print(Fore.LIGHTBLUE_EX + f'Website resolved to IP: {ip}' + Fore.LIGHTBLUE_EX)
                except socket.error as e:
                    print(Fore.RED + f'Error resolving {ip}: {e}' + Fore.LIGHTBLUE_EX)
                    continue
            scan_results, total_time = perform_scans(ip)
            print_scan_results(ip, scan_results, total_time)

    elif args.target:
        target = args.target
        if not target.count('.') == 3:
            print(Fore.LIGHTBLUE_EX + 'Resolving website ' + Fore.CYAN + str(target) + Fore.LIGHTBLUE_EX + ' to IP...' + Fore.LIGHTBLUE_EX)
            try:
                target_ip = socket.gethostbyname(target)
                print(Fore.LIGHTBLUE_EX + 'Website resolved to IP: ' + Fore.YELLOW + str(target_ip) + Fore.LIGHTBLUE_EX + '\n')
                scan_results, total_time = perform_scans(target_ip)
                print_scan_results(target_ip, scan_results, total_time)
            except socket.error as e:
                print(Fore.RED + f'Error resolving {target}: {e}' + Fore.LIGHTBLUE_EX)
                sys.exit(1)
        else:
            target_ip = target
            print(Fore.LIGHTBLUE_EX + 'Scanning Target IP: ' + Fore.YELLOW + str(target_ip) + Fore.LIGHTBLUE_EX + '\n')
            scan_results, total_time = perform_scans(target_ip)
            print_scan_results(target_ip, scan_results, total_time)

    else:
        local_ip = get_local_ip()
        network = ipaddress.ip_network(f'{local_ip}/24', strict=False)
        
        print(Fore.LIGHTBLUE_EX + 'Scanning Network ' + Fore.YELLOW + str(network) + Fore.LIGHTBLUE_EX + '\n')
        devices = scan_network(network)
        print(Fore.YELLOW + str(len(devices)) + Fore.LIGHTBLUE_EX + " Devices found:")
        for device in devices:
            vendor = get_mac_vendor(device['mac'])
            print(Fore.YELLOW + str(device['ip']) + Fore.LIGHTGREEN_EX + ' ' + str(device['mac']) + ' ' + Fore.CYAN + vendor + Fore.LIGHTBLUE_EX)
        print('\n')
        for device in devices:
            scan_results, total_time = perform_scans(device['ip'])
            print_scan_results(device['ip'], scan_results, total_time)
    
    finish1_start_time = time.time()
    ff_time = finish1_start_time - final_start_time

    print(Fore.WHITE + Back.MAGENTA + 'Scan Complete...' + Back.RESET + Fore.LIGHTBLUE_EX + f' ({ff_time:.2f}s)')
    play_tone(duration=0.4)

if __name__ == "__main__":
    main()
