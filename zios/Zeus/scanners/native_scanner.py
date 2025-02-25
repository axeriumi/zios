import ctypes
from ctypes import *
import platform
from utils.native_ops import MemoryScanner
from utils.colors import Colors

class NativeScanner:
    def __init__(self):
        self.memory_scanner = MemoryScanner()
        
    def scan_process(self, pid):
        print(Colors.cyan_gradient_text("\nScanning process memory..."))
        results = self.memory_scanner.scan_process_memory(pid)
        
        if isinstance(results, str):
            print(Colors.purple_orange_text(f"Error: {results}"))
            return
            
        for region in results:
            print(Colors.green_gradient_text(
                f"Memory region at {region['address']}, "
                f"size: {region['size']}, "
                f"protection: {region['protection']}"
            ))
            
    def detect_dll_injection(self, pid):
        if platform.system() != "Windows":
            print(Colors.purple_orange_text("DLL injection detection is only supported on Windows"))
            return
            
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        
        # Get process handle
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        
        if handle:
            try:
                # Enumerate loaded modules
                from ctypes.wintypes import HANDLE, LPWSTR, DWORD
                
                GetModuleFileNameEx = ctypes.WinDLL('psapi').GetModuleFileNameExW
                GetModuleFileNameEx.argtypes = [HANDLE, HANDLE, LPWSTR, DWORD]
                GetModuleFileNameEx.restype = DWORD
                
                modules = []
                for _ in range(1024):
                    filename = ctypes.create_unicode_buffer(1024)
                    GetModuleFileNameEx(handle, None, filename, 1024)
                    if filename.value:
                        modules.append(filename.value)
                        
                print(Colors.cyan_gradient_text("\nLoaded modules:"))
                for module in modules:
                    print(Colors.green_gradient_text(f"- {module}"))
                    
            finally:
                kernel32.CloseHandle(handle) 