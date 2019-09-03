# snmpeev3

This is a tool to obtain cleartext authentication passwords from SNMPv3 packets. Still a work in progress, there is some manual modification that is needed:
1. In wireshark, find a valid SNMPv3 packet which has both **msgAuthoritativeEngineID** and **msgAuthenticationParameters** set.
2. Obtain the values for each (right click and choose "Copy as a hex stream"), and paste into the variables section of the script
3. Right-click on "Simple Network Management Protocol" and choose "Copy as a hex stream"; paste into the **msgWhole** variable.
4. Set the path to your wordlist in the **wordlist** variable.

Currently, only the SHA hash type is supported. 

The goal of this script is to perform all calculations natively in python, stripping out all unnecessary functionality to maximize speed. 

## Benchmarks
MacBook Pro (13-inch, 2017, Four Thunderbolt 3 Ports)\
3.1 GHz Intel Core i5\
8 GB 2133 MHz LPDDR3\
**1587 passwords per second**

## Future functionality:
* Add MD5 functionality.
* Auto-detect MD5/SHA. This might be a challenge as there appears to be no indication of which one is used.
* Read pcap directly and obtain relevant values
* Move processing to GPU for additional speed
* Enable command line arguments for variables
* Add minimum and maximum password length options

## References
SNMPv3 authentication process: https://vad3rblog.wordpress.com/2017/09/11/snmp/\
Snmpkey calculation simplified from: https://github.com/TheMysteriousX/SNMPv3-Hash-Generator