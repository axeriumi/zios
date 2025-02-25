import os
import ctypes
import sys

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
            # Set icon if running in Windows
            icon_path = os.path.abspath("assets/zeus_icon.ico")
            if os.path.exists(icon_path):
                ctypes.windll.kernel32.SetConsoleIcon(icon_path)
        except:
            pass 