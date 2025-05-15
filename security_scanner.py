import socket
import requests
import ssl
import re
from urllib.parse import urlparse
import argparse
import concurrent.futures

# Function to check if the target is reachable
def check_reachability(target):
    try:
        response = requests.get(target)
        if response.status_code == 200:
            print(f"Target {target} is reachable.")
            return True
        else:
            print(f"Target {target} is not reachable. Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {target}: {e}")
        return False

# Function to check for open ports
def scan_ports(target):
    open_ports = []
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 8080]
    print(f"\nScanning for open ports on {target}...")
    try:
        hostname = urlparse(target).hostname
        if not hostname:
            print("Invalid target URL, cannot extract hostname.")
            return
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.5)
            if sock.connect_ex((hostname, port)) == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            print(f"Open ports on {target}: {', '.join(map(str, open_ports))}")
        else:
            print(f"No open ports found on {target}.")
        return open_ports
    except Exception as e:
        print(f"Error during port scanning: {e}")
        return open_ports

# Function to check for basic SQL Injection vulnerabilities
def check_sql_injection(target):
    print(f"\nChecking for SQL Injection on {target}...")
    common_sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", "admin' --"]
    vulnerable = False
    base_url = urlparse(target).scheme + "://" + urlparse(target).hostname

    for payload in common_sql_payloads:
        url = f"{base_url}{payload}"
        try:
            response = requests.get(url)
            if response.status_code == 200 and 'database' in response.text:
                print(f"Potential SQL Injection vulnerability found at: {url}")
                vulnerable = True
        except Exception as e:
            print(f"Error checking {url}: {e}")
    return vulnerable

# Function to check for basic Cross-Site Scripting (XSS) vulnerabilities
def check_xss(target):
    print(f"\nChecking for Cross-Site Scripting (XSS) on {target}...")
    common_xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    vulnerable = False
    base_url = urlparse(target).scheme + "://" + urlparse(target).hostname

    for payload in common_xss_payloads:
        url = f"{base_url}{payload}"
        try:
            response = requests.get(url)
            if response.status_code == 200 and payload in response.text:
                print(f"Potential XSS vulnerability found at: {url}")
                vulnerable = True
        except Exception as e:
            print(f"Error checking {url}: {e}")
    return vulnerable

# Function to check SSL/TLS vulnerabilities
def check_ssl_tls(target):
    print(f"\nChecking SSL/TLS configuration on {target}...")
    parsed_url = urlparse(target)
    host = parsed_url.hostname
    port = 443 if parsed_url.scheme == 'https' else 80
    
    if port != 443:
        print("SSL/TLS checks are only applicable for HTTPS.")
        return False

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssl_info = ssock.getpeercert()
                print(f"SSL certificate for {host}: {ssl_info}")
                return True
    except Exception as e:
        print(f"Error checking SSL/TLS on {target}: {e}")
        return False

# Main function to run all scans
def main():
    parser = argparse.ArgumentParser(description="Security Scanning Tool")
    parser.add_argument("target", help="Target for the scan")
    parser.add_argument("--all", action="store_true", help="Run all checks (port scan, SQL, XSS, SSL/TLS)")
    args = parser.parse_args()

    if not check_reachability(args.target):
        print("Target is unreachable. Exiting scan.")
        return

    if args.all:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                "open_ports": executor.submit(scan_ports, args.target),
                "sql_injection": executor.submit(check_sql_injection, args.target),
                "xss": executor.submit(check_xss, args.target),
                "ssl_tls": executor.submit(check_ssl_tls, args.target),
            }
            results = {name: future.result() for name, future in futures.items()}
        
        print("Scan results:")
        print(f"Open Ports: {results['open_ports']}")
        print(f"SQL Injection Vulnerable: {'Yes' if results['sql_injection'] else 'No'}")
        print(f"XSS Vulnerable: {'Yes' if results['xss'] else 'No'}")
        print(f"SSL/TLS Config: {'OK' if results['ssl_tls'] else 'Potential Issues'}")

if __name__ == "__main__":
    main()
