from colorama import Fore, Style, init
import random

init(autoreset=True)

class Colors:
    def rgb_gradient(text, start_rgb, end_rgb):
        def interpolate(start, end, factor):
            return int(start + (end - start) * factor)

        lines = text.split('\n')
        result = ""
        
        for line in lines:
            if not line.strip():
                result += "\n"
                continue
                
            length = len(line)
            for i, char in enumerate(line):
                if char != ' ':
                    factor = i / (length - 1) if length > 1 else 0
                    r = interpolate(start_rgb[0], end_rgb[0], factor)
                    g = interpolate(start_rgb[1], end_rgb[1], factor)
                    b = interpolate(start_rgb[2], end_rgb[2], factor)
                    result += f"\033[38;2;{r};{g};{b}m{char}"
                else:
                    result += char
            result += "\033[0m\n"
        return result

    @staticmethod
    def purple_orange_text(text):
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def green_gradient_text(text):
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def cyan_gradient_text(text):
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

    @staticmethod
    def purple_orange_text(text):
        # Purple RGB: (147, 51, 234)
        # Orange RGB: (255, 165, 0)
        return Colors.rgb_gradient(text, (147, 51, 234), (255, 165, 0))

    @staticmethod
    def cyan_gradient_text(text):
        # Cyan RGB: (0, 255, 255)
        # Light Blue RGB: (0, 195, 255)
        return Colors.rgb_gradient(text, (0, 255, 255), (0, 195, 255))

    @staticmethod
    def green_gradient_text(text):
        # Light Green RGB: (144, 238, 144)
        # Dark Green RGB: (34, 139, 34)
        return Colors.rgb_gradient(text, (144, 238, 144), (34, 139, 34)) 