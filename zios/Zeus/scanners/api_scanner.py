import requests
import json
from concurrent.futures import ThreadPoolExecutor

class APIScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json'
        }
    
    def check_methods(self, url):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD']
        findings = []
        
        for method in methods:
            try:
                response = requests.request(method, url, headers=self.headers, timeout=5)
                if response.status_code != 404:
                    findings.append(f"Method {method} allowed: {response.status_code}")
            except:
                continue
        return findings

    def check_jwt_vulnerabilities(self, token):
        vulnerabilities = []
        
        # Check for none algorithm
        header = token.split('.')[0]
        try:
            decoded_header = json.loads(base64.b64decode(header + '=' * (-len(header) % 4)))
            if decoded_header.get('alg').lower() == 'none':
                vulnerabilities.append("JWT uses 'none' algorithm")
        except:
            pass
            
        # Check for weak signature
        if len(token.split('.')) != 3:
            vulnerabilities.append("Malformed JWT token")
            
        return vulnerabilities

    def fuzz_parameters(self, url, params):
        payloads = ["'", "\"", "<script>", "../../", "true", "false", "null", "1=1"]
        findings = []
        
        for param in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    response = requests.get(url, params=test_params, headers=self.headers)
                    if any(error in response.text.lower() for error in 
                          ['error', 'exception', 'syntax', 'invalid']):
                        findings.append(f"Possible vulnerability in parameter {param} with payload: {payload}")
                except:
                    continue
        
        return findings 