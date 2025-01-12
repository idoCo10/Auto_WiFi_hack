Description

This Bash script automates the process of scanning, attacking, and cracking Wi-Fi networks. It combines network scanning, deauthentication attacks, and dictionary-based password cracking to simplify the process of testing Wi-Fi network security.

> ⚠️ Disclaimer: This script is intended for educational and penetration testing purposes only. Unauthorized use to attack networks without permission is illegal and unethical. Use responsibly.




---

Features

Wi-Fi Network Scanning:

Detects available Wi-Fi networks and displays detailed information, including:

SSID (Network Name)

Encryption Type

Channel

Signal Strength (Power)

BSSID (MAC Address)

Client Count


Automatically organizes and sorts scan results for easy readability.


Client Device Identification:

Identifies client devices connected to specific Wi-Fi networks.

Displays vendor information using OUI lookups.


Deauthentication Attack:

Executes deauthentication attacks to force clients to disconnect from the network.

Captures WPA handshakes during the attack.


Password Cracking:

Uses captured WPA handshakes to attempt password cracking via a dictionary attack (e.g., rockyou.txt).

Validates captured handshakes before cracking.


Automatic Handshake Handling:

Detects and skips networks with already cracked passwords or previously failed attempts.


Open Network Detection:

Automatically skips open (unencrypted) networks.




---

How It Works

1. Network Scanning:

Scans for nearby Wi-Fi networks for a specified duration.

Outputs organized scan results with all relevant details.



2. Target Selection:

Prompts the user to choose a network based on the scan results.

Automatically validates the selected network's availability.



3. Deauthentication Attack:

Attempts to capture a WPA handshake by deauthenticating client devices.

Repeats the attack up to a defined number of attempts.



4. Handshake Validation and Cracking:

If a handshake is captured, the script validates it and starts a dictionary attack to crack the Wi-Fi password.



5. Device Scanning:

Scans for client devices connected to the target network.

Displays MAC addresses and vendor details for all connected devices.





---

Requirements

Operating System:

Kali Linux


Dependencies:

The script install the required dependencies.




---

Usage

1. Clone the repository:

git clone https://github.com/idoCo10/Auto_WiFi_hack.git
cd Auto_WiFi_hack


2. Make the script executable:

chmod +x Auto_WiFi_hack.sh


3. Run the script with administrative privileges:

sudo ./Auto_WiFi_hack.sh


---

Output Details

Wi-Fi Network List: Displays all detected networks with details like SSID, encryption type, and client count.

Client Devices: Shows MAC addresses and vendor information of devices connected to the selected network.

Captured Handshakes: Validates and saves successful handshakes.

Cracked Passwords: Outputs cracked passwords for selected networks.



---

Important Notes

File Management:

Scan results are saved in a structured format for easy review.

Captured handshakes and cracked passwords are logged for future reference.


Error Handling:

Skips open networks and networks with unsupported encryption (e.g., WPA3).

Alerts the user if no handshakes are captured or if cracking fails.




---

Legal Disclaimer

This tool is for authorized penetration testing and educational purposes only.
Using this script against networks without explicit permission is illegal and violates ethical standards.
The authors are not responsible for misuse of this tool.


---

License

This project is licensed under the MIT License. See the LICENSE file for more information.


---

Contributions

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request for any suggestions.

