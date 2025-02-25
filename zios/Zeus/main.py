import os
import colorama
import time
import requests
from colorama import Fore
import webbrowser
from urllib.parse import urljoin
from utils.colors import Colors
from payloads.payload_manager import PayloadManager
from scanners.vulnerability_scanner import VulnerabilityScanner
from scanners.web_scanner import WebScanner
from scanners.api_scanner import APIScanner
from payloads.advanced_payloads import AdvancedPayloadGenerator
from scanners.advanced_scanner import AdvancedScanner
from scanners.native_scanner import NativeScanner
import sys
import numpy as np
from PIL import Image, ImageSequence
from shutil import get_terminal_size
import getpass
import re
from terminal_config import set_terminal_title, set_terminal_icon
import ctypes

os.system('cls' if os.name == 'nt' else 'clear')

colorama.init(autoreset=True)

def load_payloads_xss(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    return []

payloads_folder = "Payloads"
xss_payloads_file = os.path.join(payloads_folder, "xss.txt")

xss_payloads = load_payloads_xss(xss_payloads_file)

def load_payloads_sqli(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    return []

payloads_folder_sql = "Payloads/Sqli"
sql_payloads_file = os.path.join(payloads_folder, "xor.txt")

sql_payloads = load_payloads_xss(sql_payloads_file)

def payload_scan_xss(url):
    for payload in xss_payloads:
        url_payload_scanner_xss = f"{url}{payload}"
        response = requests.get(url)
        if payload in response.text:
            print(f"{Fore.GREEN}[+] XSS Vulnerability Found at: {url_payload_scanner_xss}")
        else:
            print(f"{Fore.RED}[-] No XSS at: {url_payload_scanner_xss}")

def payload_scan_sql(url):
    for payload in sql_payloads:
        url_payload_scanner_sql = f"{url}{payload}"
        response = requests.get(url_payload_scanner_sql)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            print(f"{Fore.GREEN}[+] SQL Injection Vulnerability Found at: {url_payload_scanner_sql}")
        else:
            print(f"{Fore.RED}[-] No SQL Injection at: {url_payload_scanner_sql}")

def url_scanner_checker(url, valid_file, invalid_file):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"{Fore.GREEN}200 - {url}{Fore.WHITE}")
            with open(valid_file, "a") as v_file:
                v_file.write(url + "\n")
        elif response.status_code == 404:
            print(f"{Fore.RED}404 - {url}{Fore.WHITE}")
            with open(invalid_file, "a") as i_file:
                i_file.write(url + "\n")
        else:
            print(f"{Fore.YELLOW}{response.status_code} - {url}{Fore.WHITE}")
            with open(invalid_file, "a") as i_file:
                i_file.write(url + "\n")
    except requests.RequestException:
        print(f"{Fore.RED}Invalid URL - {url}{Fore.WHITE}")
        with open(invalid_file, "a") as i_file:
            i_file.write(url + "\n")

def rgb_to_ansi(r, g, b):
    """Convert RGB values to ANSI escape code."""
    return f"\033[38;2;{r};{g};{b}m"

def generate_colored_gradient(text):
    """Apply a gradient to the text."""
    lines = text.split('\n')
    colored_text = ""

    num_lines = len(lines)
    for i, line in enumerate(lines):
        # Determine color transition based on position in the text
        ratio = i / num_lines
        r = int(255 * (1 - ratio))  # Red decreases
        g = int(255 * ratio)        # Green increases
        b = 255                      # Blue stays constant

        # Apply the color to the line
        colored_text += rgb_to_ansi(r, g, b) + line + "\033[0m\n"
    
    return colored_text

def get_gradient_color(position, start_color, end_color):
    """Generate a color in a gradient between start and end colors."""
    r = int(start_color[0] + (end_color[0] - start_color[0]) * position)
    g = int(start_color[1] + (end_color[1] - start_color[1]) * position)
    b = int(start_color[2] + (end_color[2] - start_color[2]) * position)
    return (r, g, b)

def image_to_ascii(image, term_width, term_height):
    """Convert image to ASCII art with proper sizing."""
    # Convert image to RGB mode if it isn't already
    image = image.convert('RGB')
    
    # Calculate the best fit size while maintaining aspect ratio
    image_ratio = image.width / image.height
    term_ratio = term_width / term_height
    
    # Adjust for terminal character aspect ratio (characters are taller than wide)
    term_width = int(term_width * 0.5)  # Adjust for character width/height ratio
    
    if term_ratio > image_ratio:
        new_height = min(term_height, image.height)
        new_width = int(new_height * image_ratio)
    else:
        new_width = min(term_width, image.width)
        new_height = int(new_width / image_ratio)
    
    image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
    pixels = np.array(image)
    
    # Use block character for better resolution
    ascii_chars = np.asarray(list('█'))
    
    # Calculate brightness
    brightness = pixels.sum(axis=2) / 3
    brightness = (brightness - brightness.min()) / (brightness.max() - brightness.min() + 1e-8)
    ascii_indices = (brightness * (len(ascii_chars) - 1)).astype(int)
    
    # Generate gradient colors (purple to orange)
    start_color = (128, 0, 128)  # Purple
    end_color = (255, 165, 0)    # Orange
    
    ascii_str = ""
    for i, row in enumerate(pixels):
        for j, pixel in enumerate(row):
            pos = (i * len(row) + j) / (len(pixels) * len(row))
            color = get_gradient_color(pos, start_color, end_color)
            char = ascii_chars[ascii_indices[i, j]]
            ascii_str += rgb_to_ansi(*color) + char
        ascii_str += "\033[0m\n"
    
    return ascii_str

def extract_frames(gif_path):
    try:
        if not os.path.exists(gif_path):
            print(f"\033[31mError: Animation file '{gif_path}' not found\033[0m")
            return []
            
        term_width, term_height = get_terminal_size()
        frames = []
        
        with Image.open(gif_path) as img:
            for frame in ImageSequence.Iterator(img):
                frame_copy = frame.copy()
                ascii_frame = image_to_ascii(frame_copy, term_width, term_height)
                frames.append(ascii_frame)
        return frames
    except Exception as e:
        print(f"\033[31mError loading animation: {str(e)}\033[0m")
        return []

def display_loading_animation():
    """Display a loading animation with colored text."""
    loading_text = "Loading"
    for _ in range(3):
        print(generate_colored_gradient(loading_text + "." * _))
        time.sleep(0.5)
        clear_screen()

def display_gif_animation():
    """Display the Sniffed.gif animation."""
    gif_path = "assets/Sniffed.gif"
    
    if not os.path.exists(gif_path):
        print(generate_colored_gradient(f"Error: Animation file '{gif_path}' not found"))
        return
    
    try:
        terminal_width, terminal_height = get_terminal_size()
        width = terminal_width
        height = terminal_height * 2
        
        with Image.open(gif_path) as img:
            frames = []
            n_frames = 0
            
            for _ in ImageSequence.Iterator(img):
                n_frames += 1
            
            img.seek(0)
            
            for frame_index, frame in enumerate(ImageSequence.Iterator(img)):
                frame = frame.convert('RGB')
                frame = frame.resize((width, height), Image.Resampling.LANCZOS)
                
                ascii_frame = ""
                pixels = np.array(frame)
                
                for i in range(0, height - 1, 2):
                    for j in range(width):
                        r1, g1, b1 = pixels[i, j]
                        r2, g2, b2 = pixels[min(i + 1, height - 1), j]
                        ascii_frame += f"\033[38;2;{r1};{g1};{b1}m\033[48;2;{r2};{g2};{b2}m▀"
                    ascii_frame += "\033[0m\n"
                
                frames.append(ascii_frame)
        
        # Display animation once
        try:
            for frame in frames:
                print("\033[H\033[J", end="")
                print("\033[H", end="")
                print(frame, end="", flush=True)
                time.sleep(0.025)  # Faster animation speed
            
        except KeyboardInterrupt:
            pass
        finally:
            time.sleep(0.1)
            clear_screen()
            
    except Exception as e:
        print(generate_colored_gradient(f"Animation error: {str(e)}"))
        time.sleep(1)

def login():
    """Handle user authentication with gradient colors."""
    max_attempts = 3
    attempts = 0
    
    while attempts < max_attempts:
        print("\033[H\033[J", end="")  # Clear screen
        
        # Generate gradient colors for prompts
        purple = (128, 0, 128)
        orange = (255, 165, 0)
        
        username_color = rgb_to_ansi(*get_gradient_color(0.3, purple, orange))
        password_color = rgb_to_ansi(*get_gradient_color(0.7, purple, orange))
        
        username = input(f"{username_color}Username: \033[0m")
        password = getpass.getpass(f"{password_color}Password: \033[0m")
        
        if username == "zeus" and password == "zeus":
            print("\033[H\033[J", end="")  # Clear screen before animation
            display_gif_animation()
            return True
        
        attempts += 1
        remaining = max_attempts - attempts
        error_color = rgb_to_ansi(255, 0, 0)
        if remaining > 0:
            print(f"{error_color}Invalid credentials! {remaining} attempts remaining\033[0m")
            time.sleep(1)
    
    print(f"{error_color}Too many failed attempts. Exiting...\033[0m")
    sys.exit(1)

def print_banner():
    banner = """                  
╔═════════════════╦═══════════════════════════════╦═════════════════╗
║—————————————————║     ·▄▄▄▄•▄▄▄ .▄• ▄▌.▄▄ ·     ║—————————————————║
║—————————————————║     ▪▀·.█▌▀▄.▀·█▪██▌▐█ ▀.     ║—————————————————║
║—————————————————║     ▄█▀▀▀•▐▀▀▪▄█▌▐█▌▄▀▀▀█▄    ║—————————————————║
║—————————————————║     █▌▪▄█▀▐█▄▄▌▐█▄█▌▐█▄▪▐█    ║—————————————————║
║—————————————————║     ·▀▀▀ • ▀▀▀  ▀▀▀  ▀▀▀▀     ║—————————————————║
║═════════════════╩═══════════════════════════════╬═════════════════╣
║[1] Subdomain Enumeration                        ║Devs Kilza,Z3RO  ║
║[2] SSL Vulnerability Check                      ║Z3RO info:       ║   
║[3] WAF Detection                                ║                 ║
║[4] Misconfiguration Check                       ║Z3RO info: ↓     ║
║[5] Open Ports Check                             ║Dc user: ↓       ║
║[6] DNS Zone Transfer Check                      ║"313top"         ║
║[7] WordPress Vuln Check                         ║                 ║
║[8] CORS Misconfig Check                         ║Kilza info: ↓    ║
║[9] File Upload Bypass Check                     ║Dc user: ↓       ║
║[10] Real IP Check                               ║"alialmoed12123" ║
║[11] SQL Injection Check                         ║                 ║
║[12] SAML Injection Check                        ╠═════════════════╣
║[13] XSS Injection Check                         ║the tool is free ║
║[14] SSRF Vulnerability Check                    ║for everyone and ║
║[15] XXE Vulnerability Check                     ║its opensource   ║
║[16] RCE Vulnerability Check                     ║but its trash    ║
║[17] Deface Target                               ║asf ngl          ║
║[18] OAuth Vulnerability Check                   ║                 ║
║[19] Exit                                        ║                 ║
╚═════════════════════════════════════════════════╩═════════════════╝
"""
    print(generate_colored_gradient(banner))

def rainbow_text(text):
    """Return text with a rainbow gradient effect."""
    colors = [
        "\033[31m",  # Red
        "\033[33m",  # Yellow
        "\033[32m",  # Green
        "\033[36m",  # Cyan
        "\033[34m",  # Blue
        "\033[35m",  # Magenta
    ]
    rainbow = ""
    for i, char in enumerate(text):
        rainbow += colors[i % len(colors)] + char
    return rainbow + "\033[0m"  # Reset color

def print_menu():
    print(Colors.purple_orange_text("Select an option:"))
    print("1. Subdomain Enumeration")
    print("2. SSL Vulnerability Check")
    print("3. WAF Detection")
    print("4. Misconfiguration Check")
    print("5. Open Ports Check")
    print("6. DNS Zone Transfer Check")
    print("7. WordPress Vulnerability Check")
    print("8. CORS Misconfiguration Check")
    print("9. File Upload Bypass Check")
    print("10. Real IP Check")
    print("11. SQL Injection Check")
    print("12. SAML Injection Check")
    print("13. XSS Injection Check")
    print("14. SSRF Vulnerability Check")
    print("15. XXE Vulnerability Check")
    print("16. RCE Vulnerability Check")
    print("17. Deface Target")
    print("18. OAuth Vulnerability Check")
    print("19. Exit")

def handle_native_operations():
    print(Colors.cyan_gradient_text("\nNative Operations Menu:"))
    print(Colors.green_gradient_text("""
    1. Scan Process Memory
    2. Detect DLL Injection
    3. Back to Main Menu
    """))
    
    choice = input(Colors.purple_orange_text("Select an option: "))
    
    if choice == "1":
        pid = int(input(Colors.green_gradient_text("\nEnter process ID to scan: ")))
        scanner = NativeScanner()
        scanner.scan_process(pid)
    elif choice == "2":
        pid = int(input(Colors.green_gradient_text("\nEnter process ID to check: ")))
        scanner = NativeScanner()
        scanner.detect_dll_injection(pid)

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def set_terminal_title():
    """Set the terminal title to Zeus"""
    if os.name == 'nt':  # Windows
        ctypes.windll.kernel32.SetConsoleTitleW("Zeus")
    else:  # Linux/Mac
        sys.stdout.write("\x1b]2;Zeus\x07")

def set_terminal_icon():
    """Set the terminal icon (Windows only)"""
    if os.name == 'nt':
        try:
            icon_path = os.path.abspath("assets/zeused.ico")
            if os.path.exists(icon_path):
                ctypes.windll.kernel32.SetConsoleIcon(icon_path)
        except Exception as e:
            print(f"Error setting icon: {str(e)}")

def print_results(title, results):
    """Print results with the same gradient coloring as the menu."""
    output = f"\n{title}:\n"
    if isinstance(results, list):
        for item in results:
            output += f"  • {str(item)}\n"
    else:
        output += f"  • {str(results)}\n"
    print(generate_colored_gradient(output))

def main():
    set_terminal_title()
    set_terminal_icon()
    
    if not login():
        return
        
    # Display GIF animation once
    display_gif_animation()
    
    # Clear the screen after the GIF
    clear_screen()
    
    # Display loading message with colors
    display_loading_animation()
    
    clear_screen()
    print_banner()
    
    # Initialize scanners
    scanner = VulnerabilityScanner()
    web_scanner = WebScanner()
    api_scanner = APIScanner()
    adv_scanner = AdvancedScanner()
    payload_gen = AdvancedPayloadGenerator()
    
    while True:
        try:
            # Get user input
            choice = input(rgb_to_ansi(0, 255, 255) + "┌──(Zeus@Kilza's)\n└─⛥ " + "\033[0m").lower()
            
            if choice == "cls" or choice == "clear":
                clear_screen()
                print_banner()
                continue
                
            # Menu options
            if choice == "1":
                url = input(generate_colored_gradient("\nEnter target URL: "))
                print(generate_colored_gradient("\n[*] Starting Subdomain Enumeration..."))
                subdomains = adv_scanner.subdomain_enumeration(url)
                print_results("Subdomain Enumeration Results", subdomains)
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "2":
                domain = input(generate_colored_gradient("\nEnter domain: "))
                print(generate_colored_gradient("\n[*] Checking SSL vulnerabilities..."))
                vulnerabilities = adv_scanner.check_ssl_vulnerabilities(domain)
                print_results("SSL Vulnerability Results", vulnerabilities)
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "3":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                waf_results = adv_scanner.check_waf_presence(url)
                print(f"WAF Detection Results: {waf_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "4":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                misconfig_results = adv_scanner.check_misconfigurations(url)
                print(f"Misconfiguration Results: {misconfig_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "5":
                host = input(Colors.purple_orange_text("\nEnter target host: "))
                open_ports = adv_scanner.check_open_ports_advanced(host)
                print(f"Open Ports: {open_ports}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "6":
                domain = input(Colors.purple_orange_text("\nEnter domain: "))
                zone_transfer_results = adv_scanner.check_dns_zone_transfer(domain)
                print(f"DNS Zone Transfer Results: {zone_transfer_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "7":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                wp_vuln_results = adv_scanner.check_wordpress_vulnerabilities(url)
                print(f"WordPress Vulnerabilities: {wp_vuln_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "8":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                cors_results = adv_scanner.check_cors_misconfig_advanced(url)
                print(f"CORS Misconfiguration Results: {cors_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "9":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                upload_results = adv_scanner.check_file_upload_vulnerabilities(url)
                print(f"File Upload Bypass Results: {upload_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "10":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                real_ip = adv_scanner.find_real_ip(url)
                print(f"Real IP of {url}: {real_ip}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "11":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                sql_injection_results = adv_scanner.check_sql_injection(url)
                print(f"SQL Injection Results: {sql_injection_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "12":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                saml_injection_results = adv_scanner.check_saml_injection(url)
                print(f"SAML Injection Results: {saml_injection_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "13":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                xss_injection_results = adv_scanner.check_xss_injection(url)
                print(f"XSS Injection Results: {xss_injection_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "14":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                ssrf_results = adv_scanner.check_ssrf_vulnerabilities(url)
                print(f"SSRF Vulnerability Results: {ssrf_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "15":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                xxe_results = adv_scanner.check_xxe_vulnerabilities(url)
                print(f"XXE Vulnerability Results: {xxe_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "16":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                rce_results = adv_scanner.check_rce_vulnerabilities(url)
                print(f"RCE Vulnerability Results: {rce_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "17":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                deface_result = adv_scanner.deface_target(url)
                print(deface_result)
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "18":
                url = input(Colors.purple_orange_text("\nEnter target URL: "))
                oauth_results = adv_scanner.check_oauth_vulnerabilities(url)
                print(f"OAuth Vulnerability Results: {oauth_results}")
                input(generate_colored_gradient("\nPress Enter to continue..."))
                clear_screen()
                print_banner()

            elif choice == "19" or choice == "exit" or choice == "quit":
                print(generate_colored_gradient("\n[*] Exiting Zeus Framework..."))
                time.sleep(1)
                clear_screen()
                break
                
        except KeyboardInterrupt:
            print(generate_colored_gradient("\n\n[!] Ctrl+C detected. Use 'exit' to quit properly."))
            continue
        except Exception as e:
            print(generate_colored_gradient(f"\n[!] Error: {str(e)}"))
            input(generate_colored_gradient("\nPress Enter to continue..."))
            clear_screen()
            print_banner()
            continue

def check_subdomain_enumeration(domain):
    """Advanced subdomain enumeration using multiple techniques."""
    try:
        results = {
            'subdomains': [],
            'vulnerabilities': [],
            'info': []
        }
        
        # DNS enumeration
        dns_command = f"""
        dig +nocmd {domain} any +multiline +noall +answer;
        for sub in $(cat wordlists/subdomains.txt); do
            dig +nocmd $sub.{domain} any +multiline +noall +answer;
        done
        """
        
        # Certificate transparency
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(ct_url)
        if response.status_code == 200:
            cert_data = response.json()
            for entry in cert_data:
                results['subdomains'].append(entry['name_value'])
        
        # Rapid7 FDNS
        fdns_query = f"""
        curl -s "https://sonar.omnisint.io/subdomains/{domain}" | jq -r '.[]'
        """
        
        # Implement Go-based fast scanner
        go_scanner = """
        package main

        import (
            "fmt"
            "net"
            "sync"
            "time"
        )

        func checkSubdomain(subdomain string, wg *sync.WaitGroup, results chan<- string) {
            defer wg.Done()
            _, err := net.LookupHost(subdomain)
            if err == nil {
                results <- subdomain
            }
        }

        func main() {
            domain := os.Args[1]
            subdomains := make(chan string, 100)
            var wg sync.WaitGroup

            for _, sub := range wordlist {
                wg.Add(1)
                go checkSubdomain(sub + "." + domain, &wg, subdomains)
            }

            go func() {
                wg.Wait()
                close(subdomains)
            }()

            for subdomain := range subdomains {
                fmt.Println(subdomain)
            }
        }
        """
        
        # Save Go code and compile
        with open("subdomain_scanner.go", "w") as f:
            f.write(go_scanner)
        
        os.system("go build subdomain_scanner.go")
        
        # Execute Go scanner
        go_results = os.popen(f"./subdomain_scanner {domain}").read()
        for subdomain in go_results.splitlines():
            results['subdomains'].append(subdomain)
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

def check_sql_injection(url, params=None):
    """Advanced SQL injection testing with multiple techniques."""
    try:
        results = {
            'vulnerabilities': [],
            'payloads_tested': [],
            'successful_payloads': []
        }
        
        # Basic SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' WAITFOR DELAY '0:0:5'--",
            "') OR ('1'='1",
            "' OR 1=1#",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        # Advanced time-based detection
        def check_time_based(url, payload):
            start_time = time.time()
            response = requests.get(f"{url}{payload}")
            execution_time = time.time() - start_time
            return execution_time > 5
        
        # Error-based detection using regex patterns
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Driver.* SQL[\w\s]*Server",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft SQL Native Client.*"
        ]
        
        # C-based fast payload testing
        shellcode = """
        #include <stdio.h>
        #include <curl/curl.h>
        #include <string.h>

        size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
            return size * nmemb;
        }

        int main(int argc, char *argv[]) {
            CURL *curl;
            CURLcode res;
            char url[1024];
            
            curl = curl_easy_init();
            if(curl) {
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                
                for(int i = 1; i < argc; i++) {
                    snprintf(url, sizeof(url), "%s%s", argv[1], argv[i]);
                    curl_easy_setopt(curl, CURLOPT_URL, url);
                    res = curl_easy_perform(curl);
                    
                    if(res != CURLE_OK)
                        fprintf(stderr, "Failed: %s\\n", curl_easy_strerror(res));
                }
                
                curl_easy_cleanup(curl);
            }
            return 0;
        }
        """
        
        # Compile and use C scanner
        with open("sql_scanner.c", "w") as f:
            f.write(shellcode)
        
        os.system("gcc sql_scanner.c -lcurl -o sql_scanner")
        
        # Test each payload
        for payload in payloads:
            results['payloads_tested'].append(payload)
            
            # Use C scanner for speed
            os.system(f"./sql_scanner {url} {payload}")
            
            # Time-based detection
            if check_time_based(url, payload):
                results['vulnerabilities'].append({
                    'type': 'time_based',
                    'payload': payload,
                    'url': url
                })
                results['successful_payloads'].append(payload)
            
            # Error-based detection
            response = requests.get(f"{url}{payload}")
            for pattern in error_patterns:
                if re.search(pattern, response.text):
                    results['vulnerabilities'].append({
                        'type': 'error_based',
                        'payload': payload,
                        'url': url,
                        'pattern': pattern
                    })
                    results['successful_payloads'].append(payload)
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

def check_xss_vulnerabilities(url):
    """Advanced XSS detection using multiple techniques and languages."""
    try:
        results = {
            'vulnerabilities': [],
            'payloads_tested': [],
            'successful_payloads': []
        }
        
        # Go-based fast DOM scanner
        go_scanner = """
        package main

        import (
            "fmt"
            "net/http"
            "strings"
            "sync"
            "golang.org/x/net/html"
        )

        func checkDOMXSS(url, payload string, wg *sync.WaitGroup, results chan<- string) {
            defer wg.Done()
            
            resp, err := http.Get(url + payload)
            if err != nil {
                return
            }
            defer resp.Body.Close()
            
            doc, err := html.Parse(resp.Body)
            if err != nil {
                return
            }
            
            var checkNode func(*html.Node)
            checkNode = func(n *html.Node) {
                if n.Type == html.ElementNode {
                    for _, attr := range n.Attr {
                        if strings.Contains(attr.Val, payload) {
                            results <- fmt.Sprintf("XSS found in %s attribute of %s tag", attr.Key, n.Data)
                            return
                        }
                    }
                }
                for c := n.FirstChild; c != nil; c = c.NextSibling {
                    checkNode(c)
                }
            }
            
            checkNode(doc)
        }

        func main() {
            url := os.Args[1]
            payloads := []string{
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "'-alert(1)-'",
                "\"><script>alert(1)</script>"
            }
            
            results := make(chan string, 100)
            var wg sync.WaitGroup
            
            for _, payload := range payloads {
                wg.Add(1)
                go checkDOMXSS(url, payload, &wg, results)
            }
            
            go func() {
                wg.Wait()
                close(results)
            }()
            
            for result := range results {
                fmt.Println(result)
            }
        }
        """
        
        # C-based fast reflection checker
        reflection_checker = """
        #include <stdio.h>
        #include <curl/curl.h>
        #include <string.h>
        #include <stdlib.h>

        struct Response {
            char *data;
            size_t size;
        };

        size_t write_callback(void *ptr, size_t size, size_t nmemb, struct Response *response) {
            size_t new_size = response->size + size * nmemb;
            response->data = realloc(response->data, new_size + 1);
            memcpy(response->data + response->size, ptr, size * nmemb);
            response->size = new_size;
            response->data[new_size] = '\\0';
            return size * nmemb;
        }

        int check_reflection(const char *url, const char *payload) {
            CURL *curl;
            CURLcode res;
            struct Response response = {0};
            char full_url[2048];
            
            snprintf(full_url, sizeof(full_url), "%s%s", url, payload);
            
            curl = curl_easy_init();
            if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, full_url);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
                
                res = curl_easy_perform(curl);
                
                if(res == CURLE_OK && strstr(response.data, payload) != NULL) {
                    printf("Reflection found with payload: %s\\n", payload);
                    free(response.data);
                    curl_easy_cleanup(curl);
                    return 1;
                }
                
                free(response.data);
                curl_easy_cleanup(curl);
            }
            return 0;
        }

        int main(int argc, char *argv[]) {
            if(argc < 2) return 1;
            
            const char *payloads[] = {
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "'-alert(1)-'",
                "\"><script>alert(1)</script>"
            };
            
            int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
            
            for(int i = 0; i < num_payloads; i++) {
                check_reflection(argv[1], payloads[i]);
            }
            
            return 0;
        }
        """
        
        # Save and compile scanners
        with open("xss_scanner.go", "w") as f:
            f.write(go_scanner)
        
        with open("reflection_checker.c", "w") as f:
            f.write(reflection_checker)
        
        os.system("go build xss_scanner.go")
        os.system("gcc reflection_checker.c -lcurl -o reflection_checker")
        
        # Run scanners
        go_results = os.popen(f"./xss_scanner {url}").read().splitlines()
        c_results = os.popen(f"./reflection_checker {url}").read().splitlines()
        
        # Process results
        for result in go_results:
            results['vulnerabilities'].append({
                'type': 'dom_xss',
                'details': result,
                'url': url
            })
            
        for result in c_results:
            results['vulnerabilities'].append({
                'type': 'reflected_xss',
                'details': result,
                'url': url
            })
        
        # Additional Python-based checks
        advanced_payloads = [
            '"><img src=x onerror=confirm(document.domain)>',
            '"><svg><script>alert(1)</script>',
            '"><iframe srcdoc="<img src=x onerror=alert(1)>">',
            '"><math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
            '"><noscript><p title="</noscript><img src=x onerror=alert(1)>">'
        ]
        
        for payload in advanced_payloads:
            response = requests.get(f"{url}{payload}")
            if payload in response.text:
                results['vulnerabilities'].append({
                    'type': 'advanced_xss',
                    'payload': payload,
                    'url': url
                })
                results['successful_payloads'].append(payload)
        
        return results
        
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    main()