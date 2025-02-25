import requests
from urllib.parse import urljoin, urlparse
import re
from concurrent.futures import ThreadPoolExecutor
from utils.helpers import NetworkHelper

class WebScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.common_paths = [
            '/api/', '/admin/', '/backup/', '/wp-admin/', '/phpinfo.php',
            '/.git/', '/.env', '/config.php', '/debug.php', '/test.php'
        ]
        self.helper = NetworkHelper()
        
    def check_cors(self, url):
        try:
            headers = {
                'Origin': 'https://evil.com'
            }
            response = requests.get(url, headers=headers)
            issues = []
            
            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    issues.append('CORS misconfiguration - wildcard origin allowed')
                elif 'evil.com' in response.headers['Access-Control-Allow-Origin']:
                    issues.append('CORS misconfiguration - reflecting origin')
            
            return issues
        except:
            return ["Could not check CORS configuration"]

    def check_headers(self, url):
        try:
            response = requests.get(url)
            headers = response.headers
            issues = []
            
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header - potential clickjacking risk',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content Security Policy'
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    issues.append(message)
            
            return issues
        except:
            return ["Could not connect to the target"]

    def directory_scan(self, base_url, wordlist=None):
        found_dirs = []
        paths = wordlist if wordlist else self.common_paths
        
        def check_path(path):
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, headers=self.headers, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    return url, response.status_code
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, path) for path in paths]
            for future in futures:
                result = future.result()
                if result:
                    found_dirs.append(result)
                    
        return found_dirs 