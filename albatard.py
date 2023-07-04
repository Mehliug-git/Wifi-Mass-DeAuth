from scapy.all import *
from prettytable import PrettyTable
import subprocess


#Demande au user le nom de la carte wifi 


#conf si le user n'a rien mis
if len(sys.argv) < 2:
    print("Donne commme arguments ton interface wifi de base & le nom de la carte monitor mode")
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
            channel = int(ord(packet[Dot11Elt:3].info))
            if bssid not in ssid_set:
                ssid_set.add(bssid)
                networks.append((bssid, ssid, channel))

    # Configuration de l'interface en mode Monitor
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")

    # Capture des paquets WiFi pendant une durée spécifiée
    sniff(iface=f"{wlanmon}", prn=packet_handler, timeout=10)

    return networks

# Fonction pour afficher les réseaux WiFi
def display_wifi_networks(networks):
    table = PrettyTable(["Adresse MAC", "Nom du réseau", "Canal"])
    for network in networks:
        table.add_row(network)
    print(table)

# Appel de la fonction pour scanner les réseaux WiFi
networks = scan_wifi_networks()

# Affichage des réseaux WiFi
display_wifi_networks(networks)


#prise d'infos (client pour deauth)
if bssid != False:
    command = f"airodump-ng --bssid {bssid} --channel {channel} {wlanmon}"

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Lire la sortie de la commande
    output, error = process.communicate()

    if error:
        print("ERROR :", error.decode())
    else:

        print(output.decode())



"""

    # Restauration de la configuration de l'interface
    os.system(f"ifconfig {wlanmon} down")
    os.system(f"iwconfig {wlanmon} mode managed")
    os.system(f"ifconfig {wlanmon} up")

"""