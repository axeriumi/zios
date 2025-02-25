import os
import json
import subprocess
from typing import Dict, Any

class ScannerManager:
    def __init__(self):
        self.scanners_path = "scanners"
        self.compile_scanners()

    def compile_scanners(self):
        """Compile all Go and C scanners."""
        # Compile Go scanners
        go_files = [
            "ssrf_scanner.go",
            "xss_scanner.go",
            # Add other Go scanners here
        ]
        
        for go_file in go_files:
            try:
                subprocess.run([
                    "go", "build",
                    "-o", f"{self.scanners_path}/go/{go_file.replace('.go', '')}",
                    f"{self.scanners_path}/go/{go_file}"
                ], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error compiling {go_file}: {e}")

        # Compile C scanners
        c_files = [
            ("rce_scanner.c", "rce_scanner"),
            ("sql_scanner.c", "sql_scanner"),
            # Add other C scanners here
        ]
        
        for c_file, output in c_files:
            try:
                subprocess.run([
                    "gcc",
                    f"{self.scanners_path}/c/{c_file}",
                    "-o", f"{self.scanners_path}/c/{output}",
                    "-lcurl", "-ljson-c", "-lpthread"
                ], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error compiling {c_file}: {e}")

    def run_scanner(self, scanner_type: str, target: str) -> Dict[str, Any]:
        """Run a specific scanner and return results."""
        try:
            if scanner_type == "ssrf":
                result = subprocess.run(
                    [f"{self.scanners_path}/go/ssrf_scanner", target],
                    capture_output=True,
                    text=True
                )
                return json.loads(result.stdout)
            
            elif scanner_type == "rce":
                result = subprocess.run(
                    [f"{self.scanners_path}/c/rce_scanner", target],
                    capture_output=True,
                    text=True
                )
                return json.loads(result.stdout)
            
            # Add other scanner types here
            
        except Exception as e:
            return {"error": str(e)}

    def scan_target(self, target: str, scan_types: list) -> Dict[str, Any]:
        """Run multiple scanners on a target."""
        results = {}
        for scan_type in scan_types:
            results[scan_type] = self.run_scanner(scan_type, target)
        return results 