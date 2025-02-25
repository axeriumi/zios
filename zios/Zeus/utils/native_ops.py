import ctypes
from ctypes import c_int, c_char_p, c_void_p, POINTER, Structure
import platform

# Load the appropriate C library based on the operating system
if platform.system() == "Windows":
    libc = ctypes.CDLL("msvcrt")
else:
    libc = ctypes.CDLL("libc.so.6")

class MemoryScanner:
    class MEMORY_BASIC_INFORMATION(Structure):
        _fields_ = [
            ("BaseAddress", c_void_p),
            ("AllocationBase", c_void_p),
            ("AllocationProtect", c_int),
            ("RegionSize", c_void_p),
            ("State", c_int),
            ("Protect", c_int),
            ("Type", c_int)
        ]

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True) if platform.system() == "Windows" else None

    def scan_process_memory(self, pid):
        if platform.system() != "Windows":
            return "Memory scanning is currently only supported on Windows"

        results = []
        handle = self.kernel32.OpenProcess(0x0010, False, pid)
        
        if handle:
            try:
                address = 0
                mbi = self.MEMORY_BASIC_INFORMATION()
                
                while self.kernel32.VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    if mbi.State & 0x1000 and mbi.Protect & 0x04:  # MEM_COMMIT and PAGE_READWRITE
                        buffer = ctypes.create_string_buffer(mbi.RegionSize)
                        bytes_read = c_int(0)
                        
                        if self.kernel32.ReadProcessMemory(handle, address, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                            results.append({
                                "address": hex(address),
                                "size": mbi.RegionSize,
                                "protection": mbi.Protect
                            })
                            
                    address += mbi.RegionSize
            finally:
                self.kernel32.CloseHandle(handle)
                
        return results 