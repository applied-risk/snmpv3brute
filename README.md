# snmpv3brute.py
**Author:** Scott Thomas for Applied Risk

**Blog post here:** https://applied-risk.com/resources/brute-forcing-snmpv3-authentication

This is a tool to obtain cleartext authentication passwords from SNMPv3 packets. 

A single SNMPv3 packet contains all of the information needed to calculate and bruteforce guess passwords. 

This bruteforcer takes inspiration from other projects out there; but the goal of this script is to perform all calculations natively in python, stripping out all unnecessary functionality to maximize speed. 

## Usage:

```wrap
$ python3 snmpv3brute.py -h
usage: snmpv3brute.py [-h] [-a [{md5,sha,all}]] [-w WORDLIST]
                   [-W [SINGLEWORD [SINGLEWORD ...]]] [-p PCAPFILE]
                   [-m SNMP SNMP SNMP] [-v]

snmpv3brute.py - SNMPv3 Authentication Bruteforcer

optional arguments:
  -h, --help            show this help message and exit
  -a [{md5,sha,all}]    Use md5, sha, or both for hashing algorithm (default: all)
  -w WORDLIST           Specify wordlist to use (1 word per line)
  -W [SINGLEWORD [SINGLEWORD ...]]
                        Specify words to use as password for testing
  -p PCAPFILE           Specify .pcap/.pcapng file with SNMP data
  -m SNMP SNMP SNMP     Manually specify msgAuthoriativeEngineID, msgAuthenticationParameters, and msgWhole from Wireshark (in that order)
  -v                    Verbose; print error messages
  ```
This program can read a PCAP (-p), extract information needed from SNMP sessions, and use a wordlist (-w) to try to bruteforce the authentication password.

Example: `python3 snmpv3brute.py -w wordlist.txt -p foo.pcapng`

Words can be submitted for testing (-W) instead of a wordlist; words should be separated by a space.

Example: `python3 snmpv3brute.py -W password1 password2 password 3 -p foo.pcapng`

Words can also be submitted with a wordlist; the program will try the words before using the wordlist.

Example: `python3 snmpv3brute.py -W password1 password2 -p foo.pcapng -w wordlist.txt`

The required SNMP variables can be submitted instead of a PCAP using the "-m" option. First, find a SNMPv3 packet in Wireshark. For msgAuthoritativeEngineID and msgAuthenticationParameters, right click on the packet field of the same name and select "Copy as Hex Stream". For msgWhole, right click on Simple Network Management Protocol, and select "Copy as Hex Stream".

Example: `python3 snmpv3brute.py -m <msgAuthoriativeEngineID> <msgAuthenticationParameters> <msgWhole> -w wordlist.txt`

Example: `python3 snmpv3brute.py -m 80001f888056417b0bd201d85d00000000 a34b57081ff0cef821e4da43 3081dc020103301002043cabfa64020205c0040103020103043f303d041180001f888056417b0bd201d85d00000000020101020200a20409736e6d705f75736572040ca34b57081ff0cef821e4da430408bec2e5f547aaa89c048183dfe158807f83a660d37264c7f397a8a42c237988ee829c52b003f6d772df683c51acb56bb327a36ee590e1d65c9466e9d18a48e80539e5fff12006d2fba6bc61756956285b84bafe773b6359d2273db3b6e49f89a6609a86ac5f440d4bfa55b17af5a81db1fa0030402bba9befad240addc41d9b394d0fb2c4a3f5ffde3730485cdaf6`

*Note: sample pcaps and wordlists are included in the test_files directory.*

## Benchmarks
MacBook Pro (13-inch, 2017, Four Thunderbolt 3 Ports)\
3.1 GHz Intel Core i5\
8 GB 2133 MHz LPDDR3\
**~800 passwords per second**

## Future functionality:
* ~~Add MD5 functionality.~~
* ~~Auto-detect MD5/SHA.~~ This is no apparent way to do this
* ~~Read pcap directly and obtain relevant values~~
* Move processing to GPU for additional speed
* ~~Enable command line arguments for variables~~
* Add minimum and maximum password length options

## References
SNMPv3 authentication process: https://vad3rblog.wordpress.com/2017/09/11/snmp/

Snmpkey calculation simplified from: https://github.com/TheMysteriousX/SNMPv3-Hash-Generator
