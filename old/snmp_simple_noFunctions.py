'''
AuthKey calculation simplified from python implementation of snmpkey:
https://github.com/TheMysteriousX/SNMPv3-Hash-Generator

Write-up of process:
https://vad3rblog.wordpress.com/2017/09/11/snmp/

[To-Do] Bruteforce process ported from here:
https://github.com/SalimHaddou/snmp0wn-md5/blob/master/snmp0wn-md5.sh
'''

import hashlib
import base64
from itertools import repeat
from binascii import unhexlify

'''
Get the data for the following variables from a SNMPv3 packet in Wireshark. 
For msgAuthoritaiveEngineID, right click on the item of the same name and select "Copy as Hex Stream" and paste here.
For msgAuthenticationParameters, right click on the item of the same name and select "Copy as Hex Stream" and paste here.
For msgWhole, right click on Simple Network Management Protocol, select "Copy as Hex Stream" and paste here.
[To-Do] Determine if offsets are constant for msgAuthEngineID and msgAuthParam, and just grab them from msgWhole.
'''
msgAuthoritativeEngineID    = '80001f8880a919a2347169675d00000000'
msgAuthenticationParameters = '9302fe84910db7726fccfe81'
msgWhole                    = '307d020103301102043ad4e4e2020300ffe304010502010304333031041180001f8880a919a2347169675d0000000002010202012d0406666f6f626172040c9302fe84910db7726fccfe8104003030041180001f8880a919a2347169675d000000000400a11902044db7478a020100020100300b300906052b060102010500'
msgWhole                    =  msgWhole.replace(msgAuthenticationParameters,'0'*24)

# Constants
dictionary = "dico.txt"
ipad = '36'*64
opad = '5c'*64
l    = 1048576

with open(dictionary) as f:
    for passphrase in f:
        K1 = ''
        K2 = ''
        passphrase = passphrase.rstrip()
        print("Trying {}".format(passphrase))
        # Calculate AuthKey
        reps = l // len(passphrase) + 1
        data = (''.join(list(repeat(passphrase, reps)))[:l]).encode('utf-8')
        Ku = hashlib.sha1(data).digest()
        E = bytearray.fromhex(msgAuthoritativeEngineID)
        AuthKey = hashlib.sha1(b''.join([Ku, E, Ku])).digest().hex()
#        print("AuthKey: {} (Length {})".format(AuthKey,len(AuthKey)))
        AuthKeyExtended = AuthKey+('0'*88)
#        print("AuthKeyExtended: {} (Length {})".format(AuthKeyExtended,len(AuthKeyExtended)))

        # Calculate testMsgAuthenticationParameters
        K1 = '{0:0{1}x}'.format((int(AuthKeyExtended, 16) ^ int(ipad, 16)),128)            
#        print("K1: {} (Length {})".format(K1,len(K1)))
        K2 = '{0:0{1}x}'.format((int(AuthKeyExtended, 16) ^ int(opad, 16)),128)
#        K2 = '{:x}'.format(int(AuthKeyExtended, 16) ^ int(opad, 16))
#        print("K2: {} (Length {})".format(K2,len(K2)))
        hashK1 = hashlib.sha1(unhexlify(K1+msgWhole)).hexdigest()
#        print("HashK1: {} (Length {})".format(hashK1,len(hashK1)))
#        if len(K2+hashK1)
        hashK2 = hashlib.sha1(unhexlify(K2+hashK1)).hexdigest()
#        print(hashK2)
        testMsgAuthenticationParameters = hashK2[0:24]

        if testMsgAuthenticationParameters == msgAuthenticationParameters:
            print("Found! The password is {}".format(passphrase))
            exit()

print("Password not found :(")
        
