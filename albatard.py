from scapy.all import *
from scapy.layers import *
from prettytable import PrettyTable
import subprocess
import threading


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
    
    def execute_command(command):
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        print("Output:")
        print(output.decode())
    
    command = f"airodump-ng --bssid {bssid} --channel {channel} {wlanmon}"
    
    # Définition de la fonction pour exécuter la commande dans un thread avec un timeout
    def execute_command_with_timeout():
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
        def timeout_handler():
            process.terminate()
    
        timeout = 5
        timer = threading.Timer(timeout, timeout_handler)
        timer.start()
    
        stdout, stderr = process.communicate()
        timer.cancel()
    
        output = str(stdout.decode())

        #me trouver la MAC du client sur la wifi 
        lines = output.split("\n")
        last_line = lines[-1].strip()
        mac_addresses = last_line.split()
        if len(mac_addresses) >= 2:
            client = mac_addresses[1]
            print("Client:", client)
        else:
            print("No client found.")
    
    # Appel de la fonction pour exécuter la commande avec le timeout
    execute_command_with_timeout()

else:
    print("[-] Aucun réseau !")





# kill monitor mode
os.system(f"ifconfig {wlanmon} down")
os.system(f"iwconfig {wlanmon} mode managed")
os.system(f"ifconfig {wlanmon} up")

