Saktiman.py - Advanced Python Remote Access Tool

Author: Security Researcher
Version: 2.0
License: MIT (Ethical Use Only)

Description
Saktiman.py is an advanced Python-based Remote Access Tool (RAT) designed for authorized penetration testing and educational purposes only. It automates payload generation, Metasploit handler setup, and payload delivery commands for multiple platforms including Windows, Linux, macOS, Android, and Python.

Features
- Supports payload generation for Windows, Android, Linux, macOS, and Python.
- Automatic handler script creation and background startup.
- Delivery commands tailored for each platform.
- Persistence option for Windows payloads.
- Simple interactive menu with payload generation and session management.
- Built-in IP detection and configuration.

⚠️ Legal Warning
This tool is strictly for authorized security testing on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

Installation and Usage on Kali Linux
1. Update your system (optional but recommended):
   sudo apt update && sudo apt upgrade -y

2. Install Metasploit Framework (if not already installed):
   Check if installed:
      msfconsole --version
   If missing, install it:
      sudo apt install metasploit-framework -y

3. Install Python 3 and pip3 (if not installed):
   Check versions:
      python3 --version
      pip3 --version
   Install if needed:
      sudo apt install python3 python3-pip -y

4. Clone the repository:
   git clone https://github.com/renatochuck/saktiman.py.git
   cd saktiman.py

5. Install Python dependencies:
   pip3 install colorama

6. Ensure msfvenom and msfconsole are available:
   which msfvenom
   which msfconsole
   They should return paths like /usr/bin/msfvenom. If not, reinstall Metasploit Framework.

7. Run the tool:
   python3 saktiman.py

8. How to use:
   - Select Generate payload from the menu.
   - Choose the target platform (Windows, Linux, Android, etc.).
   - Enter LHOST (your Kali machine IP) or leave blank for auto-detection.
   - Enter LPORT or press enter for default 4444.
   - Enter payload name or press enter for a random name.
   - Payload will be generated, and Metasploit handler will start automatically.
   - Use the delivery commands to deliver the payload to the target.
   - Manage active sessions via the session management menu.

9. Find your Kali Linux IP address:
   ip a
   Look for the active network interface and note the IPv4 address (e.g., 192.168.x.x).

Notes
- Run with sudo if you face permission issues:
   sudo python3 saktiman.py
- Ensure port 4444 (or chosen port) is not blocked by firewall.
- Always test on authorized systems only.

License
MIT License. Use responsibly and ethically.

Contact
For questions or contributions, open an issue or pull request in this repository.
