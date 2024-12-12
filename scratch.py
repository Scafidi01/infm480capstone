

def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024')  # Scan well-known ports
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for protocol in scanner[host].all_protocols():
            print(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in ports:
                print(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")