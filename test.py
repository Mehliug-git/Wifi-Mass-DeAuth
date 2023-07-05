output = """CH 1 ][ Elapsed: 12 s ][ 2023-07-05 08:53

BSSID PWR RXQ Beacons #Data, #/s CH MB ENC CIPHER AUTH ESSID

DE:AF:3B:EF:A7:B9 -30 100 112 0 0 1 180 WPA2 CCMP PSK shell

BSSID STATION PWR Rate Lost Frames Notes Probes

DE:AF:3B:EF:A7:B9 8E:A6:CA:BD:B3:04 -23 0 - 1e 1 3"""

lines = output.split("\n")
last_line = lines[-1].strip()
mac_addresses = last_line.split()
if len(mac_addresses) >= 2:
    user = mac_addresses[1]
    print("User:", user)
else:
    print("No user found.")
