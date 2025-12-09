#!/usr/bin/env python3
"""
EDUCATIONAL PURPOSE ONLY - Network Reconnaissance Tutorial
This tutorial demonstrates network reconnaissance techniques for educational and defensive purposes.

LEGAL DISCLAIMER:
This code is for educational purposes only. Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal and unethical.
"""

import socket
import threading
import subprocess
import requests
import dns.resolver
import whois
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

class NetworkReconnaissance:
    def __init__(self, target):
        self.target = target
        self.results = {}
        
    def port_scanning(self, start_port=1, end_port=1024, threads=100):
        """
        Port Scanning Tutorial
        Demonstrates various port scanning techniques
        """
        print("=== Port Scanning Tutorial ===")
        print(f"Target: {self.target}")
        print(f"Port range: {start_port}-{end_port}")
        print(f"Threads: {threads}")
        
        open_ports = []
        
        def scan_port(port):
            """Scan a single port"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    return port
            except Exception as e:
                pass
            return None
        
        print("\n1. TCP Connect Scan:")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_port, port) for port in range(start_port, end_port + 1)]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(f"✅ Port {result} is open")
        
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        print(f"Open ports found: {open_ports}")
        
        return open_ports
    
    def service_enumeration(self, open_ports):
        """
        Service Enumeration Tutorial
        Demonstrates how to identify services running on open ports
        """
        print("\n=== Service Enumeration Tutorial ===")
        
        # Common port to service mapping
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            5984: 'CouchDB',
            9200: 'Elasticsearch'
        }
        
        print("1. Common Service Identification:")
        for port in open_ports:
            service = common_services.get(port, 'Unknown')
            print(f"Port {port}: {service}")
        
        print("\n2. Banner Grabbing:")
        for port in open_ports[:5]:  # Limit to first 5 ports for demo
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target, port))
                
                # Send a simple request to get banner
                if port in [80, 8080, 8000]:
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
                elif port == 21:
                    pass  # FTP banner comes automatically
                elif port == 22:
                    pass  # SSH banner comes automatically
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if banner:
                    print(f"Port {port} banner: {banner[:100]}...")
                    
            except Exception as e:
                print(f"Port {port}: Could not grab banner - {e}")
    
    def dns_enumeration(self):
        """
        DNS Enumeration Tutorial
        Demonstrates various DNS enumeration techniques
        """
        print("\n=== DNS Enumeration Tutorial ===")
        
        try:
            print("1. DNS Records:")
            
            # A records
            try:
                a_records = dns.resolver.resolve(self.target, 'A')
                print(f"A records for {self.target}:")
                for record in a_records:
                    print(f"  {record}")
            except Exception as e:
                print(f"A record lookup failed: {e}")
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(self.target, 'MX')
                print(f"\nMX records for {self.target}:")
                for record in mx_records:
                    print(f"  {record}")
            except Exception as e:
                print(f"MX record lookup failed: {e}")
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(self.target, 'NS')
                print(f"\nNS records for {self.target}:")
                for record in ns_records:
                    print(f"  {record}")
            except Exception as e:
                print(f"NS record lookup failed: {e}")
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(self.target, 'TXT')
                print(f"\nTXT records for {self.target}:")
                for record in txt_records:
                    print(f"  {record}")
            except Exception as e:
                print(f"TXT record lookup failed: {e}")
            
            # CNAME records
            try:
                cname_records = dns.resolver.resolve(self.target, 'CNAME')
                print(f"\nCNAME records for {self.target}:")
                for record in cname_records:
                    print(f"  {record}")
            except Exception as e:
                print(f"CNAME record lookup failed: {e}")
            
            print("\n2. Reverse DNS Lookup:")
            try:
                ip = socket.gethostbyname(self.target)
                print(f"IP address: {ip}")
                
                # Reverse DNS
                hostname = socket.gethostbyaddr(ip)
                print(f"Reverse DNS: {hostname[0]}")
            except Exception as e:
                print(f"Reverse DNS lookup failed: {e}")
            
        except Exception as e:
            print(f"DNS enumeration failed: {e}")
    
    def subdomain_enumeration(self):
        """
        Subdomain Enumeration Tutorial
        Demonstrates various subdomain discovery techniques
        """
        print("\n=== Subdomain Enumeration Tutorial ===")
        
        # Common subdomain list
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'support', 'help', 'docs',
            'app', 'mobile', 'cdn', 'static', 'assets', 'img',
            'secure', 'login', 'portal', 'dashboard', 'panel'
        ]
        
        print("1. Brute Force Subdomain Discovery:")
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.target}"
            try:
                ip = socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                print(f"✅ Found: {full_domain} -> {ip}")
            except socket.gaierror:
                pass  # Subdomain doesn't exist
        
        print(f"\nFound {len(found_subdomains)} subdomains")
        
        print("\n2. Certificate Transparency Logs:")
        # This would typically use a service like crt.sh
        print("Note: In a real scenario, you would query certificate transparency logs")
        print("Services like crt.sh, censys.io, or shodan.io can be used")
        
        return found_subdomains
    
    def whois_lookup(self):
        """
        WHOIS Lookup Tutorial
        Demonstrates WHOIS information gathering
        """
        print("\n=== WHOIS Lookup Tutorial ===")
        
        try:
            print(f"WHOIS information for {self.target}:")
            w = whois.whois(self.target)
            
            print(f"Domain name: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation date: {w.creation_date}")
            print(f"Expiration date: {w.expiration_date}")
            print(f"Name servers: {w.name_servers}")
            
            if w.emails:
                print(f"Contact emails: {w.emails}")
            
            if w.org:
                print(f"Organization: {w.org}")
            
            if w.country:
                print(f"Country: {w.country}")
            
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")
    
    def web_technology_detection(self):
        """
        Web Technology Detection Tutorial
        Demonstrates how to identify web technologies
        """
        print("\n=== Web Technology Detection Tutorial ===")
        
        try:
            print(f"Analyzing web technologies for {self.target}")
            
            # Check HTTP and HTTPS
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{self.target}"
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    
                    print(f"\n{protocol.upper()} Response:")
                    print(f"Status Code: {response.status_code}")
                    print(f"Server: {response.headers.get('Server', 'Not specified')}")
                    print(f"X-Powered-By: {response.headers.get('X-Powered-By', 'Not specified')}")
                    print(f"Content-Type: {response.headers.get('Content-Type', 'Not specified')}")
                    
                    # Check for common technologies
                    server = response.headers.get('Server', '').lower()
                    powered_by = response.headers.get('X-Powered-By', '').lower()
                    content = response.text.lower()
                    
                    technologies = []
                    
                    # Web servers
                    if 'apache' in server:
                        technologies.append('Apache')
                    elif 'nginx' in server:
                        technologies.append('Nginx')
                    elif 'iis' in server:
                        technologies.append('IIS')
                    
                    # Programming languages
                    if 'php' in powered_by or 'php' in server:
                        technologies.append('PHP')
                    elif 'asp.net' in powered_by:
                        technologies.append('ASP.NET')
                    elif 'python' in powered_by:
                        technologies.append('Python')
                    elif 'node' in powered_by:
                        technologies.append('Node.js')
                    
                    # Frameworks
                    if 'wordpress' in content:
                        technologies.append('WordPress')
                    elif 'drupal' in content:
                        technologies.append('Drupal')
                    elif 'joomla' in content:
                        technologies.append('Joomla')
                    elif 'django' in content:
                        technologies.append('Django')
                    elif 'flask' in content:
                        technologies.append('Flask')
                    
                    # JavaScript frameworks
                    if 'react' in content:
                        technologies.append('React')
                    elif 'angular' in content:
                        technologies.append('Angular')
                    elif 'vue' in content:
                        technologies.append('Vue.js')
                    elif 'jquery' in content:
                        technologies.append('jQuery')
                    
                    if technologies:
                        print(f"Detected technologies: {', '.join(technologies)}")
                    
                    break  # Found working protocol, no need to check the other
                    
                except requests.exceptions.RequestException as e:
                    print(f"{protocol.upper()} connection failed: {e}")
            
        except Exception as e:
            print(f"Web technology detection failed: {e}")
    
    def directory_enumeration(self):
        """
        Directory Enumeration Tutorial
        Demonstrates web directory and file discovery
        """
        print("\n=== Directory Enumeration Tutorial ===")
        
        # Common directories and files
        common_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/backup', '/config', '/test', '/dev', '/staging', '/api',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/.env',
            '/readme.txt', '/changelog.txt', '/license.txt'
        ]
        
        print("1. Common Directory/File Discovery:")
        found_paths = []
        
        for protocol in ['http', 'https']:
            try:
                base_url = f"{protocol}://{self.target}"
                response = requests.get(base_url, timeout=5)
                if response.status_code == 200:
                    break
            except:
                continue
        else:
            print("❌ Could not connect to web server")
            return found_paths
        
        for path in common_paths:
            try:
                url = f"{base_url}{path}"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    found_paths.append(path)
                    print(f"✅ Found: {path} (Status: {response.status_code})")
                elif response.status_code == 403:
                    print(f"🔒 Forbidden: {path} (Status: {response.status_code})")
                elif response.status_code == 401:
                    print(f"🔐 Unauthorized: {path} (Status: {response.status_code})")
                
            except requests.exceptions.RequestException:
                pass
        
        print(f"\nFound {len(found_paths)} accessible paths")
        return found_paths
    
    def network_mapping(self):
        """
        Network Mapping Tutorial
        Demonstrates network topology discovery
        """
        print("\n=== Network Mapping Tutorial ===")
        
        try:
            # Get target IP
            target_ip = socket.gethostbyname(self.target)
            print(f"Target IP: {target_ip}")
            
            # Determine network range
            ip_obj = ipaddress.ip_address(target_ip)
            
            # Check if it's a private IP
            if ip_obj.is_private:
                print("Target is in private IP range")
                
                # Generate network range for scanning
                if target_ip.startswith('192.168.'):
                    network = f"{target_ip.rsplit('.', 1)[0]}.0/24"
                elif target_ip.startswith('10.'):
                    network = f"{target_ip.rsplit('.', 2)[0]}.0.0/16"
                elif target_ip.startswith('172.'):
                    second_octet = target_ip.split('.')[1]
                    if 16 <= int(second_octet) <= 31:
                        network = f"172.{second_octet}.0.0/16"
                
                print(f"Network range: {network}")
                
                # Ping sweep
                print("\n2. Ping Sweep:")
                network_obj = ipaddress.ip_network(network)
                live_hosts = []
                
                for ip in network_obj.hosts():
                    try:
                        # Use ping command
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                              capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            live_hosts.append(str(ip))
                            print(f"✅ Live host: {ip}")
                    except:
                        pass
                
                print(f"Found {len(live_hosts)} live hosts in the network")
                
            else:
                print("Target is a public IP address")
                print("Note: Network mapping for public IPs requires different techniques")
                
        except Exception as e:
            print(f"Network mapping failed: {e}")
    
    def run_reconnaissance(self):
        """
        Run complete network reconnaissance
        """
        print("🔍 Network Reconnaissance Tutorial - Educational Purpose Only")
        print("=" * 60)
        print(f"Target: {self.target}")
        print("=" * 60)
        
        try:
            # Step 1: Port scanning
            open_ports = self.port_scanning()
            
            # Step 2: Service enumeration
            if open_ports:
                self.service_enumeration(open_ports)
            
            # Step 3: DNS enumeration
            self.dns_enumeration()
            
            # Step 4: Subdomain enumeration
            self.subdomain_enumeration()
            
            # Step 5: WHOIS lookup
            self.whois_lookup()
            
            # Step 6: Web technology detection
            self.web_technology_detection()
            
            # Step 7: Directory enumeration
            self.directory_enumeration()
            
            # Step 8: Network mapping
            self.network_mapping()
            
        except Exception as e:
            print(f"❌ Error during reconnaissance: {e}")
        
        print("\n" + "=" * 60)
        print("✅ Reconnaissance completed!")
        print("Remember: Always use these techniques responsibly and legally!")

def main():
    """
    Main function to run network reconnaissance tutorial
    """
    print("Network Reconnaissance Tutorial - Educational Purpose Only")
    print("⚠️  WARNING: Use only on systems you own or have explicit permission to test!")
    
    # Get target
    target = input("Enter target IP or domain (or press Enter for localhost): ").strip()
    if not target:
        target = "localhost"
    
    # Run reconnaissance
    recon = NetworkReconnaissance(target)
    recon.run_reconnaissance()

if __name__ == "__main__":
    main()

