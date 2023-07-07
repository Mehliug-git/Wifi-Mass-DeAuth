import re

output = '''
CH 1 ][ Elapsed: 6 s ][ 2023-07-07 18:33 ][ WPA handshake: DE:AF:3B:EF:A7:B9

CH 1 ][ Elapsed: 6 s ][ 2023-07-07 18:34

BSSID PWR RXQ Beacons #Data, #/s CH MB ENC CIPHER AUTH ESSID

CE:4E:33:06:F0:96 -29 65 56 16 1 2 360 WPA2 CCMP PSK realme GT Neo2 5G

BSSID STATION PWR Rate Lost Frames Notes Probes

CE:4E:33:06:F0:96 E4:70:B8:93:AF:5D -34 1e- 1 0 2
'''

# Utilisation de la regex pour extraire le texte recherché
regex = r'WPA handshake: ([A-F0-9:]+)'
match = re.search(regex, output)

if match:
    # Récupération du résultat dans la variable "test"
    test = match.group(0)
    print(test)
else:
    print("Aucune correspondance trouvée.")
