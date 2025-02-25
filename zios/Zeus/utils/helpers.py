import requests
import socket
import dns.resolver
from urllib.parse import urlparse

class NetworkHelper:
    @staticmethod
    def is_port_open(host, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

    @staticmethod
    def get_domain_info(domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except:
            return []

    @staticmethod
    def check_url_response(url, timeout=5):
        try:
            response = requests.get(url, timeout=timeout, verify=False)
            return response.status_code, response.text
        except requests.RequestException as e:
            return None, str(e) 