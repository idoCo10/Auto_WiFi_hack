Wi-Fi Network Auto-Cracker

Overview

This Bash script automates the scanning, selection, and cracking of Wi-Fi networks using tools like aircrack-ng. Designed for advanced users, it provides functionalities such as:

Network Scanning: Automatically scans and displays Wi-Fi networks, including details like BSSID, channel, encryption, power, and connected clients.

Deauthentication Attack: Performs deauthentication attacks to capture WPA/WPA2 handshakes.

Dictionary Attack: Attempts to crack Wi-Fi passwords using the captured handshake and a dictionary file.

Vendor Detection: Identifies device vendors using their MAC addresses.

Client Analysis: Scans and displays connected clients for target networks.


⚠️ Disclaimer
This script is intended for educational and ethical purposes only. Unauthorized use to access or disrupt networks is illegal and punishable by law. Use responsibly on networks you own or have permission to test.


---

Features

Automated Wi-Fi Scanning

Detects available networks with detailed information.

Organizes data for easier target selection.


Deauthentication Attack

Disrupts target devices to capture WPA/WPA2 handshakes.


Password Cracking

Uses a dictionary-based approach to find passwords.


Device Vendor Lookup

Maps MAC addresses to manufacturer names.


User-Friendly Interface

Interactive prompts for network selection and attack execution.




---

Requirements

Linux OS with tools like aircrack-ng, awk, and grep.

Wi-Fi Adapter supporting monitor mode.

Dependencies:

airodump-ng, aireplay-ng (from aircrack-ng suite).

gnome-terminal for terminal sessions.

rockyou.txt or similar wordlist for cracking.




---

Setup

1. Clone the repository:

git clone https://github.com/yourusername/wifi-auto-cracker.git  
cd wifi-auto-cracker


2. Grant execute permissions to the script:

chmod +x wifi_auto_cracker.sh


3. Install required tools:

sudo apt-get install aircrack-ng gnome-terminal




---

Usage

1. Run the script with administrative privileges:

sudo ./wifi_auto_cracker.sh


2. Follow the interactive prompts to:

Scan available Wi-Fi networks.

Select a target network.

Perform deauthentication and handshake capture.

Crack passwords using a wordlist.





---

Output

Displays detailed information about scanned networks.

Saves handshake files and cracked passwords for future reference.



---

Example

Scanning available WiFi Networks (15 s):  
1. SSID: MyWiFi          Clients: 3  Encryption: WPA2  Channel: 6  Power: -45  BSSID: 00:11:22:33:44:55  
2. SSID: OpenNetwork     Clients: 0  Encryption: OPN   Channel: 11 Power: -60  BSSID: 66:77:88:99:AA:BB  

Enter row number: 1  

Starting deauth attack ->>  
Attempting to capture handshake...  

->> Got the handshake!  
Cracking password with rockyou.txt...  
Wi-Fi password is: password123


---

Notes

Output Storage: Scanned data, handshakes, and cracked passwords are stored in designated directories.

Vendor File: To map MAC addresses to vendors, include an OUI file (e.g., oui.txt).



---

Legal Disclaimer

The use of this script without explicit authorization is prohibited. It is the user's responsibility to comply with applicable laws and regulations.


