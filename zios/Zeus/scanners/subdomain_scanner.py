import os
import requests
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

class SubdomainScanner:
    def __init__(self):
        self.wordlist_path = "wordlists/subdomains.txt"
        self.results = {
            'subdomains': [],
            'vulnerabilities': [],
            'info': []
        }

    def compile_go_scanner(self):
        go_code = """
        package main

        import (
            "fmt"
            "net"
            "sync"
            "os"
            "bufio"
        )

        func checkSubdomain(domain, wordlist string, results chan<- string) {
            file, err := os.Open(wordlist)
            if err != nil {
                return
            }
            defer file.Close()

            scanner := bufio.NewScanner(file)
            var wg sync.WaitGroup

            for scanner.Scan() {
                subdomain := scanner.Text() + "." + domain
                wg.Add(1)
                go func(sub string) {
                    defer wg.Done()
                    _, err := net.LookupHost(sub)
                    if err == nil {
                        results <- sub
                    }
                }(subdomain)
            }

            wg.Wait()
        }

        func main() {
            if len(os.Args) != 3 {
                fmt.Println("Usage: scanner <domain> <wordlist>")
                return
            }

            domain := os.Args[1]
            wordlist := os.Args[2]
            results := make(chan string, 100)

            go checkSubdomain(domain, wordlist, results)

            for result := range results {
                fmt.Println(result)
            }
        }
        """
        
        with open("scanners/go/subdomain_scanner.go", "w") as f:
            f.write(go_code)
        
        os.system("go build -o scanners/go/subdomain_scanner scanners/go/subdomain_scanner.go")

    def scan(self, domain):
        # Compile Go scanner if not exists
        if not os.path.exists("scanners/go/subdomain_scanner"):
            self.compile_go_scanner()

        # Run Go scanner
        go_results = os.popen(f"./scanners/go/subdomain_scanner {domain} {self.wordlist_path}").read()
        self.results['subdomains'].extend(go_results.splitlines())

        # Certificate transparency check
        self.check_crt_sh(domain)
        
        # DNS enumeration
        self.dns_enumeration(domain)

        return self.results

    def check_crt_sh(self, domain):
        try:
            response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if response.status_code == 200:
                for entry in response.json():
                    self.results['subdomains'].append(entry['name_value'])
        except Exception as e:
            self.results['info'].append(f"crt.sh error: {str(e)}")

    def dns_enumeration(self, domain):
        resolver = dns.resolver.Resolver()
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        
        for record in record_types:
            try:
                answers = resolver.resolve(domain, record)
                for rdata in answers:
                    self.results['info'].append(f"{record} record: {str(rdata)}")
            except Exception:
                continue 