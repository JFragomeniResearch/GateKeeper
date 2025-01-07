import colorama
from colorama import Fore, Style
from datetime import datetime

def display_banner():
    """Display the GateKeeper banner with version and timestamp"""
    # Initialize colorama for cross-platform colored output
    colorama.init()
    
    banner = f"""
{Fore.CYAN}
     ▄▄ •  ▄▄▄· ▄▄▄▄ ▄▄▄▄ ▄ •▄ ▄▄▄ .▄▄▄ . ▄▄▄·▄▄▄ .▄▄▄  
    ▐█ ▀ ▪▐█ ▀█ •██  ▀▄.▀·█▌▄▌▪▀▄.▀·▀▄.▀·▐█ ▄█▀▄.▀·▀▄ █·
    ▄█ ▀█▄▄█▀▀█  ▐█.▪▐▀▀▪▄▐▀▀▄·▐▀▀▪▄▐▀▀▪▄ ██▀·▐▀▀▪▄▐▀▀▄ 
    ▐█▄▪▐█▐█ ▪▐▌ ▐█▌·▐█▄▄▌▐█.█▌▐█▄▄▌▐█▄▄▌▐█▪·•▐█▄▄▌▐█•█▌
    ·▀▀▀▀  ▀  ▀  ▀▀▀  ▀▀▀ ·▀  ▀ ▀▀▀  ▀▀▀ .▀    ▀▀▀ .▀  ▀
{Style.RESET_ALL}
{Fore.GREEN}╔══════════════════════════════════════════════════════════╗
║  GateKeeper Network Security Scanner v1.0.0                 ║
║  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                    ║
║  Developed for Authorized Network Security Testing          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def display_scan_start(target: str, port_range: str):
    """Display information about the starting scan"""
    print(f"\n{Fore.YELLOW}[*] Starting scan...")
    print(f"[*] Target: {target}")
    print(f"[*] Port Range: {port_range}{Style.RESET_ALL}\n")

def display_scan_complete(duration: float):
    """Display scan completion message"""
    print(f"\n{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}") 