# Half-WPA-Cracker
This is a scapy based Half WPA Handshake cracker.

It uses scapy's community edition repository to parse EAP packets in order to retrieve the necessary info such as Anonce, Snonce, MIC and the communicating parties MAC addresses.

Then it uses python's multiprocessing module to make it a (kind of) powerful CPU based password cracker.


# USAGE

> use -s or --ssid to specify the SSID of the network to crack directly. I flag is not set the script will ask you for it during execution.

> use -c or --capture to specify the location of the PCAP file to read the packets from.

To provide the cracker with words to use you must pass either the Worlist parameter or STDIN.

> use -w or --wordlist to scpecify the location of the worlist file to load the password candidates from.

> use --stdin to read the words from stdin. You can use a password generator program and pipe it's output to this cracker.


# Examples

> ./half_wpa_cracker -w "wordlists.txt" -c "half_handshake_capture.cap" -s "MyWirelessTest"

Here is an example using JohnTheRipper as word generation program.

> john --wordlist="wordlists.txt" --rules=Jumbo --stdout | ./half_wpa_cracker -c "half_handshake_capture.cap" -s "MyWirelessTest" --stdin

# Getting Half WPA Handshake captures

In order to capture a Half WPA handshake one must mimick a WPA protected access point and have client trying to connect to it.
The packets of this interaction must be logged in order to capture the first 2 frames of the WPA handshake.

The easiest way to do this is by using the Evil Twin Framework that has built-in support for catchin Half WPA Handshakes.
